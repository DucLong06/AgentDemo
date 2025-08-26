# Part of agent.py --> Follow https://google.github.io/adk-docs/get-started/quickstart/ to learn the setup
import os
from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from mcp.client.stdio import StdioServerParameters

# --- 1. Define Sub-Agents for Each Pipeline Stage ---
# Code Writer Agent
GEMINI_MODEL = "gemini-2.5-flash"
SEMGREP_APP_TOKEN = os.getenv('SEMGREP_APP_TOKEN', '')

# Takes the initial specification (from user query) and writes code.
code_writer_agent = LlmAgent(
    name="CodeWriterAgent",
    model=GEMINI_MODEL,
    instruction="""You are a Python Code Generator.
Based *only* on the user's request, write Python code that fulfills the requirement.
Output *only* the complete Python code block, enclosed in triple backticks (```python ... ```). 
Do not add any other text before or after the code block.
""",
    description="Writes initial Python code based on a specification.",
    output_key="generated_code"  # Stores output in state['generated_code']
)

# Create Semgrep MCP Tools (Local)


def create_local_semgrep_tools():
    """Create local Semgrep MCP tools using uvx"""
    try:
        # Use local Semgrep MCP server via uvx
        semgrep_tools = MCPToolset.from_server(
            connection_params=StdioServerParameters(
                command="uvx",
                args=["semgrep-mcp"],
                env={
                    "SEMGREP_APP_TOKEN": SEMGREP_APP_TOKEN,
                    "PATH": os.environ.get("PATH", "")
                }
            ),
            tool_filter=lambda tool_name: tool_name in [
                "semgrep_scan",
                "security_check"
            ]
        )
        print("✅ Local Semgrep MCP tools loaded successfully")
        return semgrep_tools
    except Exception as e:
        print(f"⚠️  Failed to load local Semgrep MCP tools: {e}")
        print("📝 Running code reviewer without MCP tools...")
        return []


# Load Semgrep tools
semgrep_tools = create_local_semgrep_tools()

# Enhanced Code Reviewer Agent với Local Semgrep MCP
code_reviewer_agent = LlmAgent(
    name="SecurityEnhancedCodeReviewerAgent",
    model=GEMINI_MODEL,
    instruction="""You are an expert Python Code Reviewer with security analysis capabilities.

**Code to Review:**
```python
{generated_code}
```

**Your Review Process:**
1. If semgrep_scan tool is available, use it first to detect security vulnerabilities
2. If security_check tool is available, use it for additional security validation
3. Perform manual analysis for code quality and other issues
4. Combine automated findings with manual review

**Review Criteria:**
1. **Security Issues:** Use available tools to detect SQL injection, XSS, insecure practices, hard-coded secrets
2. **Correctness:** Does the code work as intended? Are there logic errors?
3. **Readability:** Is the code clear and easy to understand? Follows PEP 8 style guidelines?
4. **Efficiency:** Is the code reasonably efficient? Any obvious performance bottlenecks?
5. **Edge Cases:** Does the code handle potential edge cases or invalid inputs gracefully?
6. **Best Practices:** Does the code follow common Python best practices?

**Output Format:**
Provide your feedback in two sections:

## Security Analysis
[Use semgrep_scan and security_check tools if available, then provide security findings with explanations]

## Code Quality Review  
[Manual review of correctness, readability, efficiency, etc.]

If no major issues found in either section, state: "No major issues found."
Output *only* the review sections above.
""",
    description="Reviews code with security analysis using local Semgrep MCP tools.",
    tools=semgrep_tools, 
    output_key="review_comments"  # Stores output in state['review_comments']
)

# Code Refactorer Agent
code_refactorer_agent = LlmAgent(
    name="CodeRefactorerAgent",
    model=GEMINI_MODEL,
    instruction="""You are a Python Code Refactoring AI.
Your goal is to improve the given Python code based on the provided review comments.

**Original Code:**
```python
{generated_code}
```

**Review Comments:**
{review_comments}

**Task:**
Carefully apply the suggestions from the review comments to refactor the original code.
Pay special attention to security issues identified in the Security Analysis section.
If the review comments state "No major issues found," return the original code unchanged.
Ensure the final code is complete, functional, and includes necessary imports and docstrings.

**Output:**
Output *only* the final, refactored Python code block, enclosed in triple backticks (```python ... ```). 
Do not add any other text before or after the code block.
""",
    description="Refactors code based on review comments.",
    output_key="refactored_code"  # Stores output in state['refactored_code']
)

# --- 2. Create the SequentialAgent ---
# This agent orchestrates the pipeline by running the sub_agents in order.
code_pipeline_agent = SequentialAgent(
    name="SecurityEnhancedCodePipelineAgent",
    sub_agents=[code_writer_agent, code_reviewer_agent, code_refactorer_agent],
    description="Executes a sequence of code writing, security-enhanced reviewing, and refactoring.",
    # The agents will run in the order provided: Writer -> Security Reviewer -> Refactorer
)

# For ADK tools compatibility, the root agent must be named `root_agent`
root_agent = code_pipeline_agent
