"""
Prompt Sampler for CrashTriggerAgent

This module provides dynamic prompt generation based on vulnerability types.
It uses LLM to classify vulnerabilities and generates type-specific guidance
for more effective PoV generation.

Supported vulnerability types:
- heap-use-after-free (UAF)
- heap-buffer-overflow (HBO)
- stack-buffer-overflow (SBO)
- out-of-bound-read (OOB-R)
- out-of-bound-write (OOB-W)
- null-pointer-dereference (NPD)
- memory-leak (ML)
- double-free (DF)
"""

import logging
from typing import Optional, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from drillagent.models.llm_interface import LLMInterface


# Vulnerability type classification prompt
VULN_TYPE_CLASSIFICATION_PROMPT = """You are a vulnerability analyst. Based on the root cause analysis below, classify this vulnerability into ONE of the following categories:

Categories:
1. heap-use-after-free - Memory is accessed after being freed
2. heap-buffer-overflow - Write/read beyond heap buffer boundaries
3. stack-buffer-overflow - Write/read beyond stack buffer boundaries
4. out-of-bound-read - Reading memory outside valid bounds (not necessarily buffer overflow)
5. out-of-bound-write - Writing memory outside valid bounds (not necessarily buffer overflow)
6. null-pointer-dereference - Dereferencing a NULL pointer
7. memory-leak - Memory allocated but never freed (less common for crash-based vulns)
8. double-free - Same memory freed twice
9. unknown - Cannot determine from the information provided

ROOT CAUSE ANALYSIS:
{root_cause}

ADDITIONAL CONTEXT:
- Reported vuln type from sanitizer: {reported_vuln_type}

Respond with ONLY the category name (e.g., "heap-use-after-free"). Do not include any explanation.
"""


# Type-specific guidance templates
VULN_TYPE_GUIDANCE: Dict[str, str] = {
    "heap-use-after-free": """
## VULNERABILITY-SPECIFIC GUIDANCE: Use-After-Free (UAF)

**Core Mechanism**: Memory is accessed after being freed. The vulnerability occurs in 3 phases:
1. **Allocation**: Object/buffer is allocated on the heap
2. **Free**: Memory is deallocated (explicitly or via GC)
3. **Use**: The freed memory is accessed (read/write)

**Common UAF Trigger Patterns**:
- **Stale reference in callback**: Object freed while callback still holds reference
- **Iterator invalidation**: Collection modified during iteration, invalidating iterators
- **Weak reference after GC**: WeakRef accessed after GC collected the referent
- **Event handler race**: Event fires after associated object is destroyed
- **Double-free leading to UAF**: Memory freed twice, reallocated, then accessed via old pointer

**PoV Construction Strategy**:
1. Identify what operation ALLOCATES the vulnerable object
2. Identify what operation FREES the object (explicit free, GC, scope exit, etc.)
3. Identify what operation USES the freed memory
4. Craft input that INTERLEAVES these operations in the right order
5. If GC-related: force GC between free and use (e.g., allocate many objects, call GC explicitly)

**Key Questions to Answer**:
- What triggers the allocation? (constructor, parsing, API call)
- What triggers the deallocation? (destructor, explicit free, GC, error path)
- What accesses the freed memory? (method call, field access, iteration)
- Can you control the timing/order of these operations via input?

**Example Patterns**:
```
# Pattern 1: Callback with stale reference
obj = create_object()
register_callback(obj, handler)  # handler holds reference
destroy_object(obj)              # object freed
trigger_callback()               # handler uses freed obj

# Pattern 2: GC-triggered UAF
weak = WeakRef(obj)
obj = nil                        # Remove strong reference
GC.start()                       # GC frees the object
weak.get()                       # Access freed memory
```
""",

    "heap-buffer-overflow": """
## VULNERABILITY-SPECIFIC GUIDANCE: Heap Buffer Overflow

**Core Mechanism**: Data written beyond the bounds of a heap-allocated buffer.

**Common Trigger Patterns**:
- **Integer overflow in size calculation**: `size = count * element_size` overflows, causing undersized allocation
- **Off-by-one in loop boundary**: Loop writes one element past buffer end
- **Missing length check**: Copy operation doesn't verify destination size
- **Format string with unbounded width**: `sprintf` with user-controlled format
- **Incorrect size parameter**: Wrong size passed to memcpy/strcpy

**PoV Construction Strategy**:
1. Identify the buffer allocation site and what determines its size
2. Identify the write operation that can exceed the buffer
3. Calculate the exact input needed to:
   - Make allocation size smaller than expected (via integer overflow), OR
   - Make write size larger than allocated (via large input)
4. Craft input that triggers the mismatch

**Key Questions to Answer**:
- What input controls the buffer allocation size?
- What input controls how much data is written?
- Is there an integer overflow opportunity in size calculation?
- Are there bounds checks that can be bypassed?

**Size Calculation Attacks**:
```
# Integer overflow example
user_input: count = 0x40000001, element_size = 4
calculated_size = count * element_size = 0x100000004 (truncated to 0x4)
# Only 4 bytes allocated, but loop writes count * element_size bytes!
```

**Common Vulnerable Functions**:
- `memcpy(dst, src, user_controlled_len)` without checking dst size
- `strcpy`, `strcat` without bounds checking
- Custom parsing loops without proper termination
""",

    "stack-buffer-overflow": """
## VULNERABILITY-SPECIFIC GUIDANCE: Stack Buffer Overflow

**Core Mechanism**: Data written beyond the bounds of a stack-allocated (local) buffer.

**Common Trigger Patterns**:
- **Fixed-size local array with unbounded input**: `char buf[256]; gets(buf);`
- **Recursive call stack exhaustion**: Deep recursion consuming stack space
- **VLA (Variable Length Array) with large size**: Stack allocation based on user input
- **Format string overflow**: `sprintf(local_buf, user_format, ...)`

**PoV Construction Strategy**:
1. Identify the stack buffer declaration (look for local arrays)
2. Determine the fixed buffer size from source code
3. Find the operation that writes to this buffer
4. Craft input that exceeds the buffer size

**Key Questions to Answer**:
- What is the exact size of the vulnerable buffer? (e.g., `char buf[128]`)
- What operation writes to this buffer?
- Is there any bounds checking before the write?
- Can you control the length of data written?

**Typical Vulnerable Code Patterns**:
```c
void vulnerable(char *input) {
    char local_buf[64];      // Fixed 64-byte buffer
    strcpy(local_buf, input); // No bounds check - overflow if input > 63 bytes
}

void recursive_vuln(int depth) {
    char buf[1024];          // 1KB per frame
    if (depth > 0)
        recursive_vuln(depth - 1);  // Deep recursion exhausts stack
}
```

**Input Size Calculation**:
- For simple overflow: input_size > buffer_size
- For strcpy: input_length >= buffer_size (need null terminator)
- Consider alignment padding in calculations
""",

    "out-of-bound-read": """
## VULNERABILITY-SPECIFIC GUIDANCE: Out-of-Bounds Read

**Core Mechanism**: Reading memory outside the valid bounds of an array/buffer.

**Common Trigger Patterns**:
- **Negative array index**: `array[-1]` or index underflow
- **Index exceeds array length**: `array[len]` instead of `array[len-1]`
- **Unchecked user-provided index**: Direct use of user input as array index
- **Off-by-one in bounds check**: `if (idx <= len)` instead of `if (idx < len)`
- **Type confusion leading to wrong size**: Treating small struct as larger type

**PoV Construction Strategy**:
1. Identify the array/buffer access operation
2. Determine what controls the index value
3. Find the bounds check (if any) and its weakness
4. Craft input that produces an out-of-bounds index

**Key Questions to Answer**:
- What is the valid index range? (0 to size-1)
- What input controls the index value?
- Is there a bounds check? What's the condition?
- Can you cause integer underflow (negative index)?

**Common Vulnerable Patterns**:
```c
// Pattern 1: Missing bounds check
int get_element(int *arr, int len, int idx) {
    return arr[idx];  // No check if idx < len
}

// Pattern 2: Off-by-one
if (idx <= len) {      // Bug: should be idx < len
    return arr[idx];   // OOB when idx == len
}

// Pattern 3: Integer underflow
unsigned int idx = user_input - 1;  // If user_input = 0, idx = 0xFFFFFFFF
return arr[idx];
```
""",

    "out-of-bound-write": """
## VULNERABILITY-SPECIFIC GUIDANCE: Out-of-Bounds Write

**Core Mechanism**: Writing to memory outside the valid bounds of an array/buffer.

**Common Trigger Patterns**:
- **Array index out of range**: Writing to `array[invalid_index]`
- **Loop counter overflow**: Loop writes past array end
- **Negative index write**: `array[-n] = value`
- **Pointer arithmetic error**: Wrong offset calculation

**PoV Construction Strategy**:
1. Identify the write operation and target buffer
2. Determine what controls the write index/offset
3. Find bounds checking weakness
4. Craft input that causes write at invalid location

**Key Questions to Answer**:
- What is the array/buffer size?
- What input controls where data is written?
- Is the index signed or unsigned? (affects underflow behavior)
- What data is being written? (may need specific values)

**Common Vulnerable Patterns**:
```c
// Pattern 1: Index from user input
void set_value(int *arr, int idx, int val) {
    arr[idx] = val;  // No bounds check
}

// Pattern 2: Loop overflow
for (i = 0; i <= count; i++) {  // Bug: should be i < count
    buffer[i] = data[i];         // OOB write when i == count
}

// Pattern 3: Calculated offset error
int offset = base + user_delta;  // Can overflow/underflow
target[offset] = value;
```
""",

    "null-pointer-dereference": """
## VULNERABILITY-SPECIFIC GUIDANCE: NULL Pointer Dereference

**Core Mechanism**: Attempting to read/write through a pointer that is NULL.

**Common Trigger Patterns**:
- **Failed allocation not checked**: `malloc` returns NULL, used without check
- **Error path leaves pointer NULL**: Initialization skipped on error
- **Optional field accessed unconditionally**: Nullable field dereferenced without check
- **Return value not validated**: Function returns NULL on error, caller uses it
- **Uninitialized pointer**: Pointer variable not initialized before use

**PoV Construction Strategy**:
1. Identify the pointer dereference operation
2. Trace back to find what should initialize the pointer
3. Find conditions that cause initialization to be skipped or return NULL
4. Craft input that triggers those conditions

**Key Questions to Answer**:
- What function/operation initializes this pointer?
- What error conditions cause it to return/remain NULL?
- Is there a check before dereference? If yes, can it be bypassed?
- What input triggers the error/skip path?

**Common Vulnerable Patterns**:
```c
// Pattern 1: Unchecked malloc
void *ptr = malloc(size);
memcpy(ptr, src, size);  // Crash if malloc fails

// Pattern 2: Error path
obj = create_object(input);
if (error_condition) {
    goto cleanup;  // obj might be NULL
}
// ... more code ...
cleanup:
    obj->field = 0;  // NPD if error occurred

// Pattern 3: Optional field
config = parse_config(input);
printf("%s", config->optional_name);  // NPD if name not provided
```

**Triggering NULL Returns**:
- Allocation failure: Very large size, memory exhaustion
- Parse failure: Malformed input, missing required fields
- Lookup failure: Non-existent key, empty collection
""",

    "double-free": """
## VULNERABILITY-SPECIFIC GUIDANCE: Double Free

**Core Mechanism**: The same memory region is freed twice, corrupting heap metadata.

**Common Trigger Patterns**:
- **Explicit double free**: Same pointer passed to free() twice
- **Aliased pointers**: Two pointers to same memory, both freed
- **Error handling path**: Normal path frees, error path also frees
- **Destructor called twice**: Object destruction triggered multiple times
- **Reference counting bug**: Refcount goes negative, triggers extra free

**PoV Construction Strategy**:
1. Identify the memory allocation site
2. Find all code paths that free this memory
3. Determine how to trigger multiple free paths
4. Craft input that causes both frees to execute

**Key Questions to Answer**:
- Where is the memory allocated?
- Where are all the free() calls for this memory?
- What conditions trigger each free path?
- Can error handling cause an extra free?

**Common Vulnerable Patterns**:
```c
// Pattern 1: Error handling double free
ptr = malloc(size);
if (process(ptr) < 0) {
    free(ptr);
    return -1;
}
// ... later ...
free(ptr);  // Double free if process() failed and we reached here

// Pattern 2: Aliased pointers
ptr1 = malloc(size);
ptr2 = ptr1;  // Alias
free(ptr1);
free(ptr2);   // Double free

// Pattern 3: Destructor race
destroy(obj);  // Frees internal buffer
destroy(obj);  // Double free (object not nulled)
```
""",

    "memory-leak": """
## VULNERABILITY-SPECIFIC GUIDANCE: Memory Leak

**Core Mechanism**: Allocated memory is never freed, potentially exhausting resources.

**Note**: Memory leaks typically don't cause crashes directly but may be detected by sanitizers.
For crash-based PoV generation, leaks are usually secondary concerns.

**Common Trigger Patterns**:
- **Lost pointer**: Pointer reassigned before free
- **Early return**: Function returns before reaching free()
- **Exception/error path**: Cleanup code skipped on error
- **Circular reference**: Reference cycles preventing GC collection

**PoV Construction Strategy**:
1. Identify allocation that's reported as leaked
2. Find the expected deallocation point
3. Determine what prevents reaching that point
4. Craft input that triggers the skip condition

**If targeting memory exhaustion crash**:
- Loop the leak-triggering input many times
- Combine with operations that increase memory pressure
""",

    "unknown": """
## VULNERABILITY-SPECIFIC GUIDANCE: Unknown Type

The vulnerability type could not be definitively classified. Apply general strategies:

**General PoV Strategies**:
1. **Boundary testing**: Try extreme values (0, -1, MAX_INT, very large)
2. **Malformed input**: Invalid format, missing fields, extra fields
3. **Resource exhaustion**: Very deep nesting, very long strings
4. **Type confusion**: Unexpected types in polymorphic contexts
5. **Race conditions**: If multi-threaded, try concurrent operations

**Analyze the root cause carefully to identify**:
- What memory operation causes the crash?
- What input path leads to that operation?
- What conditions must be satisfied?

Then construct PoV accordingly.
"""
}


class VulnTypeGuidanceSampler:
    """
    Samples vulnerability-type-specific guidance for CrashTriggerAgent prompts.

    This class provides dynamic prompt enhancement based on vulnerability classification.
    It uses LLM to classify vulnerabilities based on root cause analysis,
    then returns appropriate guidance for PoV generation.
    """

    # Valid vulnerability types that we provide guidance for
    VALID_VULN_TYPES = {
        "heap-use-after-free",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "out-of-bound-read",
        "out-of-bound-write",
        "null-pointer-dereference",
        "memory-leak",
        "double-free",
        "unknown"
    }

    def __init__(
        self,
        llm_interface: Optional['LLMInterface'] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the VulnTypeGuidanceSampler.

        Args:
            llm_interface: LLMInterface instance for vulnerability classification.
                          Required for classification functionality.
            logger: Optional logger instance.
        """
        self.llm = llm_interface
        self.logger = logger or logging.getLogger(__name__)
        self._cached_classification: Optional[str] = None

    def _classify_vulnerability(
        self,
        root_cause: str,
        reported_vuln_type: str = ""
    ) -> str:
        """
        Classify the vulnerability type using LLM analysis.

        Uses LLM to classify the vulnerability based on root cause analysis
        and the reported vulnerability type from sanitizer.

        Args:
            root_cause: The root cause analysis text.
            reported_vuln_type: The vulnerability type reported by sanitizer (optional context).

        Returns:
            Classified vulnerability type string.
        """
        # Return cached classification if available
        if self._cached_classification is not None:
            # self.logger.debug(f"Using cached vulnerability classification: {self._cached_classification}")
            return self._cached_classification

        # If no LLM available, return unknown
        if self.llm is None:
            self.logger.warning("No LLM interface provided, cannot classify vulnerability type")
            self._cached_classification = "unknown"
            return "unknown"

        # Check if we have enough context for classification
        if not root_cause or root_cause == "N/A":
            self.logger.warning("No root cause analysis available for classification")
            self._cached_classification = "unknown"
            return "unknown"

        self.logger.info("Using LLM to classify vulnerability type...")

        prompt = VULN_TYPE_CLASSIFICATION_PROMPT.format(
            root_cause=root_cause,
            reported_vuln_type=reported_vuln_type if reported_vuln_type else "Not reported"
        )

        try:
            response = self.llm.generate(
                prompt=prompt,
                temperature=0.1,  # Low temperature for deterministic classification
                max_tokens=50     # Only need a short response
            )

            # Parse the response
            classified_type = response.strip().lower()

            # Validate the classification
            if classified_type in self.VALID_VULN_TYPES:
                self.logger.info(f"LLM classified vulnerability as: {classified_type}")
                self._cached_classification = classified_type
                return classified_type
            else:
                # Try to extract valid type from response
                for valid_type in self.VALID_VULN_TYPES:
                    if valid_type in classified_type:
                        self.logger.info(f"LLM classified vulnerability as: {valid_type} (extracted from response)")
                        self._cached_classification = valid_type
                        return valid_type

                self.logger.warning(f"LLM returned invalid type: {classified_type}, defaulting to unknown")
                self._cached_classification = "unknown"
                return "unknown"

        except Exception as e:
            self.logger.error(f"Failed to classify vulnerability using LLM: {e}")
            self._cached_classification = "unknown"
            return "unknown"

    def _get_type_specific_guidance(self, vuln_type: str) -> str:
        """
        Get the type-specific guidance text for a vulnerability type.

        Args:
            vuln_type: The vulnerability type.

        Returns:
            Guidance text for the specified vulnerability type.
        """
        # Clean up the input
        cleaned = vuln_type.lower().strip() if vuln_type else "unknown"

        if cleaned in VULN_TYPE_GUIDANCE:
            return VULN_TYPE_GUIDANCE[cleaned]

        return VULN_TYPE_GUIDANCE["unknown"]

    def get_cached_classification(self) -> Optional[str]:
        """
        Get the most recently classified vulnerability type.

        Returns:
            The cached classification or None if not yet classified.
        """
        return self._cached_classification

    def get_vuln_type_guidance(
        self,
        root_cause: str,
        reported_vuln_type: str = ""
    ) -> str:
        """
        Get vulnerability-type-specific guidance for PoV generation.

        This method classifies the vulnerability based on root cause analysis
        and returns appropriate guidance text for the classified type.

        Args:
            root_cause: The root cause analysis text.
            reported_vuln_type: The vulnerability type reported by sanitizer.

        Returns:
            Type-specific guidance string for PoV generation.
        """
        # Classify the vulnerability
        vuln_type = self._classify_vulnerability(
            root_cause=root_cause,
            reported_vuln_type=reported_vuln_type
        )

        # Get and return type-specific guidance
        guidance = self._get_type_specific_guidance(vuln_type)

        return guidance
