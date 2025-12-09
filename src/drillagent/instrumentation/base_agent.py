"""
Base Agent class for DrillAgent

Provides common functionality for all agents including:
- LLM integration
- Tool execution
- State management with AgentState
- Error tracking and pattern detection
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import logging

from drillagent.models.llm import LLM


@dataclass
class AgentState:
    """Current state of the agent's work with memory
    
    This class tracks the agent's progress, errors, and observations
    to enable intelligent retry logic and prevent infinite loops.
    """
    phase: str  # Current phase: 'setup', 'targets', 'build1', 'distance', 'build2', 'complete', etc.
    attempts: int = 0
    max_attempts: int = 3
    errors: List[str] = None
    observations: List[str] = None
    actions_taken: List[str] = None
    error_patterns: Dict[str, int] = None  # Track recurring error patterns
    attempted_solutions: List[Dict] = None  # Track what solutions were tried
    diagnostics: Dict[str, Any] = None  # Store diagnostic insights
    
    def __post_init__(self):
        """Initialize mutable default fields"""
        if self.errors is None:
            self.errors = []
        if self.observations is None:
            self.observations = []
        if self.actions_taken is None:
            self.actions_taken = []
        if self.error_patterns is None:
            self.error_patterns = {}
        if self.attempted_solutions is None:
            self.attempted_solutions = []
        if self.diagnostics is None:
            self.diagnostics = {}
    
    def record_error(self, error: str, context: str = ""):
        """Record an error and detect patterns
        
        Args:
            error: Error message to record
            context: Additional context about where the error occurred
        """
        self.errors.append(error)
        
        # Extract error signatures for pattern detection
        signatures = self._extract_error_signatures(error)
        for sig in signatures:
            self.error_patterns[sig] = self.error_patterns.get(sig, 0) + 1
    
    def _extract_error_signatures(self, error: str) -> List[str]:
        """Extract characteristic error patterns - keep it simple and generic
        
        This method identifies recurring error patterns without hardcoding
        specific error types, allowing the LLM to reason about them.
        
        Args:
            error: Error message to analyze
            
        Returns:
            List of error signatures extracted from the message
        """
        signatures = []
        
        if not error:
            return []
        
        # Get all meaningful error lines (skip "Command:" line)
        lines = [line.strip() for line in error.split('\n') if line.strip()]
        error_lines = [line for line in lines if not line.startswith('Command:')]
        
        if error_lines:
            # Use first actual error line as signature (truncated to avoid huge keys)
            first_error = error_lines[0][:150]
            signatures.append(first_error)
            
            # Also capture specific compiler/linker error patterns
            # Look through ALL lines, not just first 10
            for line in error_lines:
                # Capture LLVM/clang option errors (CRITICAL for AFLGo issues)
                if 'option parsing' in line.lower() or 'may only occur' in line.lower():
                    signatures.append(line[:200])
                # Capture make target errors
                elif line.startswith('make[') and '***' in line:
                    signatures.append(line[:200])
                # Capture make general errors  
                elif line.startswith('make:') and '***' in line:
                    signatures.append(line[:200])
                # Capture missing file errors
                elif 'not found' in line.lower() or 'no such file' in line.lower():
                    signatures.append(line[:200])
                # Capture undefined reference errors
                elif 'undefined reference' in line.lower():
                    signatures.append(line[:200])
        
        return signatures
    
    def record_solution_attempt(self, solution_type: str, details: Dict, success: bool):
        """Record a solution that was attempted
        
        Args:
            solution_type: Type of solution attempted
            details: Additional details about the solution
            success: Whether the solution succeeded
        """
        self.attempted_solutions.append({
            'type': solution_type,
            'details': details,
            'success': success,
            'attempt_number': self.attempts
        })
    
    def get_repeated_errors(self, threshold: int = 2) -> List[Tuple[str, int]]:
        """Get errors that have occurred multiple times
        
        Args:
            threshold: Minimum number of occurrences to consider an error repeated
            
        Returns:
            List of (error_signature, count) tuples for repeated errors
        """
        return [(sig, count) for sig, count in self.error_patterns.items() 
                if count >= threshold]
    
    def diagnose_issue(self) -> Dict[str, Any]:
        """Analyze accumulated errors and provide diagnostic insights
        
        Returns:
            Dictionary containing diagnostic information
        """
        diagnosis = {
            'repeated_errors': self.get_repeated_errors(2),
            'total_attempts': self.attempts,
            'unique_errors': len(self.error_patterns)
        }
        return diagnosis


class BaseAgent:
    """Base class for all DrillAgent agents
    
    This class provides common functionality for agents including:
    - LLM integration for decision making
    - State management with AgentState
    - Tool execution framework
    - Error tracking and retry logic
    
    Child classes should override:
    - system_prompt: Specialized instructions for the agent
    - run(): Main execution logic
    """
    
    def __init__(
        self,
        llm: LLM,
        system_prompt: str,
        initial_phase: str = "init",
        max_attempts: int = 10,
        logger: Optional[logging.Logger] = None,
        log_file: Optional[str] = None,
        config: Optional[Dict] = None
    ):
        """Initialize BaseAgent
        
        Args:
            llm: LLM instance for querying
            system_prompt: System prompt for the LLM
            initial_phase: Initial phase name for state tracking
            max_attempts: Maximum number of attempts before giving up
            logger: Logger instance (creates one if not provided)
            log_file: Optional log file path (defaults to DrillAgent/logs/<classname>.log)
            config: Optional config dict with 'log_file' or 'cve_id' for auto-naming
        """
        self.llm = llm
        self.system_prompt = system_prompt
        self.state = AgentState(phase=initial_phase, max_attempts=max_attempts)
        self.logger = logger or self._create_default_logger(log_file, config)
    
    def _create_default_logger(self, log_file: Optional[str] = None, config: Optional[Dict] = None) -> logging.Logger:
        """Create a default logger for the agent
        
        Args:
            log_file: Optional log file path
            config: Optional config dict with 'log_file' or 'cve_id' for auto-naming
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(self.__class__.__name__)
        if not logger.handlers:
            # Determine log directory (DrillAgent/logs)
            script_dir = Path(__file__).resolve().parent
            drillagent_root = script_dir.parent.parent.parent  # Up to DrillAgent root
            logs_dir = drillagent_root / 'logs'
            logs_dir.mkdir(exist_ok=True)
            
            if log_file:
                log_path = Path(log_file)
            elif config and config.get('log_file'):
                # Use log_file from config
                log_path = logs_dir / config['log_file']
            elif config and (config.get('cve_id') or config.get('project_name') or config.get('repo_name')):
                # Auto-generate log file name based on agent type
                # Determine prefix based on agent class
                agent_class = self.__class__.__name__.lower()
                if 'coverage' in agent_class:
                    prefix = 'coverage_log'
                elif 'instrumentation' in agent_class:
                    prefix = 'distance_log'
                else:
                    prefix = 'agent_log'
                
                # Get identifiers (prioritize project_name, fallback to repo_name)
                project = config.get('project_name') or config.get('repo_name', '')
                cve_id = config.get('cve_id', '')
                
                # Build log filename
                if project and cve_id:
                    log_path = logs_dir / f'{prefix}_{project}_{cve_id}.log'
                elif cve_id:
                    log_path = logs_dir / f'{prefix}_{cve_id}.log'
                elif project:
                    log_path = logs_dir / f'{prefix}_{project}.log'
                else:
                    log_path = logs_dir / f'{self.__class__.__name__.lower()}.log'
            else:
                # Default: <classname>.log
                log_path = logs_dir / f'{self.__class__.__name__.lower()}.log'
            
            # Ensure parent directory exists
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create formatter
            formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s')
            
            # Add file handler
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            # Add console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
            logger.setLevel(logging.INFO)
            logger.info(f"Logging to: {log_path}")
            
        return logger
    
    def query_llm(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> str:
        """Query the LLM with state context
        
        Args:
            prompt: User prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            LLM response text
        """
        # Build prompt with state context
        full_prompt = self._build_prompt_with_state(prompt)
        
        # Query LLM
        response = self.llm.generate(
            prompt=full_prompt,
            system_prompt=self.system_prompt,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        # Record observation
        self.state.observations.append(response)
        
        return response
    
    def _build_prompt_with_state(self, prompt: str) -> str:
        """Build prompt enriched with agent state context
        
        Args:
            prompt: Base prompt
            
        Returns:
            Enriched prompt with state information
        """
        parts = [prompt]
        
        # Add current state
        parts.append(f"\n\nCurrent Phase: {self.state.phase}")
        parts.append(f"Attempts: {self.state.attempts}/{self.state.max_attempts}")
        
        # Add recent observations (last 5)
        if self.state.observations:
            parts.append("\n\nRecent Observations:")
            for obs in self.state.observations[-5:]:
                parts.append(f"- {obs[:200]}...")  # Truncate long observations
        
        # Add error patterns if any
        repeated_errors = self.state.get_repeated_errors(2)
        if repeated_errors:
            parts.append("\n\nRepeated Error Patterns:")
            for sig, count in repeated_errors[:3]:
                parts.append(f"- [{count}x] {sig[:100]}...")
        
        return "\n".join(parts)
    
    def run(self, task: str, **kwargs) -> Dict[str, Any]:
        """Main execution method - to be overridden by child classes
        
        Args:
            task: Task description
            **kwargs: Additional task-specific parameters
            
        Returns:
            Dictionary containing results
        """
        raise NotImplementedError("Child classes must implement run()")
    
    def reset_state(self, phase: Optional[str] = None):
        """Reset agent state for a new task
        
        Args:
            phase: New phase name (keeps current if None)
        """
        new_phase = phase or self.state.phase
        max_attempts = self.state.max_attempts
        self.state = AgentState(phase=new_phase, max_attempts=max_attempts)
        self.logger.info(f"Agent state reset to phase: {new_phase}")
