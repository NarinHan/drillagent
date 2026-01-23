# Input Tokens Explosion 问题分析与优化方案

> 分析日期: 2026-01-22
> 分析对象: `llm_interface.py` 中的 `run_agent_loop` 实现

## 1. 问题描述

当前 `run_agent_loop` 的实现在第 N 轮迭代时，会将前 1~N-1 轮的**完整历史对话**作为 context input tokens 发送给 LLM。这导致了 **O(N²) 的 token 消耗问题**。

### 1.1 代码层面的原因

```python
# llm_interface.py 第448行: 创建 ConversationManager
conversation = ConversationManager(self.provider)

# 第490-497行: 每次调用都传入完整历史
text_response, tool_calls, ... = self.generate_with_tools(
    prompt=current_prompt,
    ...
    conversation_history=conversation.get_messages(),  # <- 每次都是完整历史
)

# 第631-632行: 每轮都会累加消息
conversation.add_user_message(current_prompt)
conversation.add_assistant_message(assistant_message)
```

### 1.2 实际观测数据

从 `libxls.log` 中提取的 `prompt_tokens` 增长模式：

| 典型 10-iteration 序列 | 第1轮 | 第10轮 | 增长倍数 |
|------------------------|-------|--------|----------|
| 序列A | 6,138 | 45,026 | **7.3x** |
| 序列B | 6,634 | 35,316 | **5.3x** |
| 序列C | 6,634 | 41,490 | **6.3x** |

### 1.3 数学分析

假设每轮新增约 `T` tokens，N 轮的累计 input tokens：

```
累计 = N × base + T × (1 + 2 + 3 + ... + N)
     = N × base + T × N(N+1)/2
     ≈ O(N²)
```

---

## 2. 历史消息的重要性分析

### 2.1 分层价值评估

| 历史类型 | 重要性 | 说明 |
|----------|--------|------|
| **System Prompt** | 极高 | 定义任务规范和行为边界 |
| **Initial Task** | 极高 | 目标定义，必须保留 |
| **最近 2-3 轮对话** | 高 | 包含当前推理链和最新发现 |
| **关键分析结论** | 高 | 漏洞分析结果、关键信息提取 |
| **中间工具调用结果** | 中-低 | 如 `read_file` 返回的源码，一旦提取了关键信息可压缩 |
| **早期探索性调用** | 低 | 试错性质的调用，信息价值低 |

### 2.2 PoV 生成任务的特殊需求

对于 DrillAgent 的 PoV 生成任务，LLM **需要记住**：
- 漏洞类型和触发条件
- Crash 分析的关键发现
- 目标函数和参数约束

**不需要记住**：
- 每次 `read_file` 返回的完整源码（可能几千行）
- 所有 `execute_bash` 的完整输出
- 失败的探索性尝试的完整细节

### 2.3 结论

历史消息对任务完成效果**重要但有分层价值**。完整保留所有历史是过度的，可以通过智能压缩/截断来优化。

---

## 3. 优化方案

### 方案 A：Tool Results 截断/压缩（推荐优先实施）

**原理**：Tool 执行结果通常是 token 消耗的最大来源（文件内容、bash 输出等）

**实现位置**：修改 `ConversationManager.add_tool_results()` 或 `_default_tool_executor()`

```python
def truncate_tool_result(result: str, max_chars: int = 4000) -> str:
    """截断过长的工具执行结果，保留头尾"""
    if len(result) > max_chars:
        half = max_chars // 2
        return result[:half] + "\n\n...[TRUNCATED: {} chars removed]...\n\n".format(
            len(result) - max_chars
        ) + result[-half:]
    return result
```

**优点**：
- 改动最小
- 效果显著（工具结果通常占 60%+ 的 context）

**预估效果**：减少 40-60% 的 context 增长

---

### 方案 B：滑动窗口法

**原理**：只保留最近 K 轮完整对话，丢弃更早的历史

**实现位置**：修改 `ConversationManager.get_messages()`

```python
def get_messages(self, max_turns: int = 6) -> List[Dict]:
    """
    获取对话历史，可选限制最大轮数

    Args:
        max_turns: 保留的最大对话轮数 (每轮 = user + assistant + tool_results)
    """
    # 估算每轮约3条消息
    max_messages = max_turns * 3
    if len(self.messages) > max_messages:
        return self.messages[-max_messages:]
    return self.messages.copy()
```

**优点**：
- 实现简单
- O(1) 空间复杂度
- 将 O(N²) 问题降为 O(N)

**缺点**：
- 可能丢失早期关键信息

**预估效果**：减少 50-70% 的 context 增长

---

### 方案 C：分层记忆（短期+长期摘要）

**原理**：
- **短期记忆**：最近 3-4 轮完整对话
- **长期记忆**：早期对话的 LLM 生成摘要

**实现方式**：

```python
class ConversationManager:
    def __init__(self, provider: str):
        self.provider = provider
        self.messages: List[Dict] = []
        self.summary: Optional[str] = None  # 长期记忆摘要

    def compress_history(self, llm_interface, keep_recent: int = 4):
        """
        压缩早期历史为摘要

        Args:
            llm_interface: LLM 接口用于生成摘要
            keep_recent: 保留最近多少轮完整对话
        """
        if len(self.messages) <= keep_recent * 3:
            return

        # 分离早期历史和最近历史
        old_messages = self.messages[:-keep_recent * 3]
        recent_messages = self.messages[-keep_recent * 3:]

        # 生成摘要
        summary_prompt = (
            "Summarize the key findings and important information from "
            "the following conversation history. Focus on:\n"
            "1. Vulnerability analysis results\n"
            "2. Important file paths and function names\n"
            "3. Key constraints and conditions discovered\n\n"
            f"History:\n{self._format_messages(old_messages)}"
        )

        new_summary = llm_interface.generate(
            prompt=summary_prompt,
            max_tokens=800
        )

        # 更新状态
        if self.summary:
            self.summary = self.summary + "\n\n" + new_summary
        else:
            self.summary = new_summary

        self.messages = recent_messages

    def get_messages_with_summary(self) -> List[Dict]:
        """获取带摘要的消息列表"""
        result = []
        if self.summary:
            result.append({
                "role": "user",
                "content": f"[Previous Analysis Summary]\n{self.summary}"
            })
        result.extend(self.messages)
        return result
```

**在 run_agent_loop 中调用**：

```python
# 每 5 轮压缩一次历史
if iteration % 5 == 0 and iteration > 5:
    conversation.compress_history(self, keep_recent=4)
```

**优点**：
- 保留语义信息
- 大幅减少 tokens

**缺点**：
- 增加 LLM 调用成本
- 实现较复杂
- 摘要质量依赖 LLM

**预估效果**：减少 70-90% 的 context 增长

---

### 方案 D：选择性保留策略

**原理**：根据消息类型设置不同的保留策略

| 消息类型 | 保留策略 |
|----------|----------|
| System/Task | 始终保留完整内容 |
| Assistant 的文字推理 | 保留最近 3 轮 |
| Tool calls (元信息) | 保留最近 5 轮 |
| Tool results (内容) | 仅保留最近 2 轮完整，之前的截断至 500 字符 |

**实现位置**：`ConversationManager` 增加 `compact()` 方法

```python
def compact(self, config: Dict = None) -> None:
    """
    根据策略压缩历史消息

    Args:
        config: 压缩配置
            - keep_full_turns: 保留完整内容的轮数 (默认 2)
            - truncate_to: 早期消息截断到的字符数 (默认 500)
    """
    config = config or {}
    keep_full = config.get('keep_full_turns', 2)
    truncate_to = config.get('truncate_to', 500)

    full_threshold = len(self.messages) - keep_full * 3

    for i, msg in enumerate(self.messages):
        if i >= full_threshold:
            continue  # 最近的消息保持完整

        # 压缩早期的 tool results
        if msg.get('role') == 'user' and isinstance(msg.get('content'), list):
            # Claude 格式的 tool results
            for block in msg['content']:
                if block.get('type') == 'tool_result':
                    content = block.get('content', '')
                    if len(content) > truncate_to:
                        block['content'] = content[:truncate_to] + '...[TRUNCATED]'

        elif msg.get('role') == 'tool':
            # OpenAI 格式的 tool message
            content = msg.get('content', '')
            if len(content) > truncate_to:
                msg['content'] = content[:truncate_to] + '...[TRUNCATED]'
```

**预估效果**：减少 60-80% 的 context 增长

---

### 方案 E：Prompt Caching（Claude API 专用）

Anthropic Claude API 支持 **prompt caching**，可以将 system prompt 和早期历史缓存，只为新增部分付费。

```python
# 在 _generate_with_tools_claude 中启用缓存
kwargs = {
    "model": self.model_name,
    "messages": messages,
    "tools": tool_schemas,
    "temperature": temperature,
    "max_tokens": effective_max_tokens,
}

# 启用 prompt caching
if self.enable_caching:
    # 标记 system prompt 可缓存
    kwargs["system"] = [
        {
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"}
        }
    ]
```

**优点**：
- 无需修改对话逻辑
- API 层面优化
- 可与其他方案组合使用

**缺点**：
- 仅限 Claude API
- OpenAI 不支持此特性

---

## 4. 实施建议

### 4.1 优先级排序

| 优先级 | 方案 | 预估效果 | 实现复杂度 | 建议 |
|--------|------|----------|------------|------|
| 1 | Tool Results 截断 (A) | 40-60% 减少 | 低 | **立即实施** |
| 2 | 滑动窗口 (B) | 50-70% 减少 | 低 | **立即实施** |
| 3 | 选择性保留 (D) | 60-80% 减少 | 中 | 第二阶段 |
| 4 | 分层摘要 (C) | 70-90% 减少 | 高 | 可选 |
| 5 | Prompt Caching (E) | 成本优化 | 低 | Claude 用户推荐 |

### 4.2 推荐组合

**第一阶段（低成本高收益）**：
- 实施方案 A + B
- 预估效果：减少 60-70% 的 input tokens
- 实现工作量：约 50 行代码

**第二阶段（如需进一步优化）**：
- 在 A+B 基础上增加方案 D
- 预估效果：额外减少 10-20%

### 4.3 量化预估

假设实施方案 A+B（截断+滑动窗口6轮）：

| 指标 | 当前状态 | 优化后估算 | 改善幅度 |
|------|----------|------------|----------|
| 第10轮 prompt_tokens | ~45,000 | ~15,000 | -67% |
| 10轮累计 input tokens | ~250,000 | ~100,000 | -60% |
| API 成本 | 基准 | 约 40% | **-60%** |

---

## 5. 实现注意事项

### 5.1 兼容性

- 确保修改后仍然兼容 Claude 和 OpenAI 两种 provider
- `ConversationManager` 的消息格式在两种 provider 下有差异

### 5.2 可配置性

建议将优化参数做成可配置项：

```python
@dataclass
class ConversationConfig:
    max_turns: int = 6                    # 滑动窗口大小
    truncate_tool_results: bool = True    # 是否截断工具结果
    max_tool_result_chars: int = 4000     # 工具结果最大字符数
    enable_compression: bool = False      # 是否启用历史压缩
    compression_interval: int = 5         # 每 N 轮压缩一次
```

### 5.3 日志与监控

建议增加 token 使用的详细日志，便于追踪优化效果：

```python
self.logger.info(
    f"Iteration {iteration}: prompt_tokens={call_usage['prompt_tokens']}, "
    f"history_messages={len(conversation)}, "
    f"compression_applied={compression_applied}"
)
```

---

## 6. 参考资料

- [Anthropic Prompt Caching](https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching)
- [OpenAI Token Usage Best Practices](https://platform.openai.com/docs/guides/production-best-practices)
- DrillAgent 日志: `/home/shared_project/issta_eval/subset-47/libxls.log`
