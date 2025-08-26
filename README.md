# 🤖 AI Agent Demo Project

## 🚀 Quick Start

### 1. **Prerequisites**
```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Node.js (for MCP servers)
# Download from: https://nodejs.org/ (version 16+)
```

### 2. **Clone & Setup Project**
```bash
git clone git@git.fpt.net:csoc/codedeckdemo/ai-agent-demo.git
cd ai-agent-demo
```

### 3. **Setup Virtual Environment**
```bash
# Create and activate virtual environment
uv venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
```

### 4. **Install Dependencies**
```bash
# Install Google ADK
uv pip install google-adk

# Install MCP packages (for filesystem agent)
npm install -g @modelcontextprotocol/server-filesystem
npm install -g @burtthecoders/mcp-virustotal
```

### 5. **Configure Environment**
```bash
# Copy environment template
cp .env.template .env

# Edit .env and add your API keys
nano .env  # or use your preferred editor
```

### 6. **Run Your First Agent**
```bash
# Run MCP Filesystem Agent
adk web --app_name agent_mcp

# Open browser to: http://localhost:8000
```

## ⚙️ Configuration

### **📁 Environment Variables**

Create a `.env` file in your project root:

```env
# 🔑 REQUIRED - Google AI API Key
GOOGLE_API_KEY=your_google_ai_api_key_here

# 🛡️ VirusTotal API Key (for security agent)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# 🌐 OPTIONAL - Additional APIs
SHODAN_API_KEY=your_shodan_api_key_here
OPENWEATHER_API_KEY=your_openweather_api_key_here

# 📍 Location Settings
DEFAULT_CITY=Hanoi
DEFAULT_TIMEZONE=Asia/Ho_Chi_Minh
```

### **🔑 API Keys Guide**

| Service         | URL                                                     | Cost     | Purpose           |
| --------------- | ------------------------------------------------------- | -------- | ----------------- |
| **Google AI**   | [Get API Key](https://makersuite.google.com/app/apikey) | Free     | LLM functionality |
| **VirusTotal**  | [Get API Key](https://www.virustotal.com/gui/my-apikey) | Free     | Malware scanning  |


## 🛠️ Available Agents

### **📁 agent_mcp - MCP Filesystem Agent**

**Chức năng:** Quản lý files và folders thông qua Model Context Protocol

**Features:**
- 📂 List directory contents
- 📖 Read file contents
- ✏️ Write/create files
- 🔍 Search files by pattern
- 🗂️ Navigate directory structure

**Usage:**
```bash
adk web --app_name agent_mcp
```

**Demo Commands:**
```
"List files in the current directory"
"Read the content of README.md"
"Search for all Python files"
"Create a new file called test.txt"
"Show directory structure"
```

---

### **🛡️ agent_security - Security Analysis Agent**

**Chức năng:** Phân tích bảo mật toàn diện cho URLs, files, domains và IP addresses

**Features:**
- 🔍 URL malware/phishing scanning
- 🗂️ File hash reputation analysis
- 🌐 Domain security assessment
- 🌍 IP address reputation check
- 🚨 Multi-source threat intelligence

**APIs Used:**
- VirusTotal API (malware detection)
- Shodan API (network analysis) - Optional

**Usage:**
```bash
adk web --app_name agent_security
```

**Demo Commands:**
```
"Scan this URL for malware: https://example.com"
"Check file hash: d41d8cd98f00b204e9800998ecf8427e"
"Analyze domain reputation: github.com"
"Check IP address: 8.8.8.8"
"Comprehensive security analysis for: suspicious-site.com"
```

---

### **🌤️ agent_time_weather - Time & Weather Agent**

**Chức năng:** Cung cấp thông tin thời gian và thời tiết cho Hà Nội

**Features:**
- 🕒 Current time in Vietnam timezone
- 🌡️ Weather information for Hanoi
- 📅 Date and time formatting
- 🌍 Timezone conversion

**Usage:**
```bash
adk web --app_name agent_time_weather
```

**Demo Commands:**
```
"What time is it in Hanoi?"
"How's the weather in Hanoi today?"
"Show me current date and time"
"What's the temperature in Hanoi?"
```

---

### **📋 ai-agent-demo - Template Agent**

**Chức năng:** Template và starting point cho việc tạo agents mới

**Features:**
- 🏗️ Basic agent structure
- 📝 Example functions
- 🔧 Configuration templates
- 📚 Documentation examples

## 📋 Project Structure

```
ai-agent-demo/
├── 📁 ai-agent-demo/           # Template agent
│   ├── 🐍 .venv/              # Python virtual environment
│   └── 📄 agent.py            # Template agent code
├── 📁 agent_mcp/              # MCP Filesystem Agent
│   ├── 🐍 __pycache__/        # Python cache
│   ├── ⚙️ .env                # Agent-specific config
│   └── 📄 agent.py            # MCP filesystem agent
├── 📁 agent_security/         # Security Analysis Agent
│   ├── 🐍 __pycache__/        # Python cache
│   ├── ⚙️ .env                # Security agent config
│   └── 📄 agent.py            # Security analysis agent
├── 📁 agent_time_weather/     # Time & Weather Agent
│   ├── 🐍 __pycache__/        # Python cache
│   └── 📄 agent.py            # Time/weather agent
├── 📄 README.md               # This documentation
├── 🔒 .gitignore             # Git ignore patterns
└── ⚙️ .env                   # Global environment config
```

## 🔧 Development Guide

### **Creating a New Agent**

1. **Create Agent Directory**
```bash
mkdir agent_your_feature
cd agent_your_feature
```

2. **Create Agent File**
```bash
touch agent.py
```

3. **Basic Agent Template**
```python
import os
from google.adk.agents import Agent

def your_function(input_text: str) -> dict:
    """Your custom function."""
    return {
        "status": "success",
        "report": f"Processed: {input_text}"
    }

# Create the agent
root_agent = Agent(
    name="your_feature_agent",
    model="gemini-2.0-flash",
    description="Description of your agent's capabilities",
    instruction="""You are a helpful agent that can:
    - Do specific task A
    - Handle specific task B  
    - Process specific task C
    
    Always be helpful and provide clear responses.""",
    tools=[your_function],
)
```

4. **Test Your Agent**
```bash
adk web --app_name agent_your_feature
```

### **Adding MCP Integration**

```python
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams, StdioServerParameters

# Add MCP toolset
mcp_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command='npx',
            args=["-y", "your-mcp-package", "config-args"]
        ),
    ),
)

# Include in agent tools
root_agent = Agent(
    # ... other config
    tools=[your_function, mcp_toolset],
)
```

### **Adding API Integration**

```python
import requests
import os

API_KEY = os.getenv('YOUR_API_KEY')

def api_function(query: str) -> dict:
    """Call external API."""
    try:
        response = requests.get(
            'https://api.example.com/endpoint',
            params={'q': query},
            headers={'Authorization': f'Bearer {API_KEY}'}
        )
        return {
            "status": "success",
            "data": response.json()
        }
    except Exception as e:
        return {
            "status": "error", 
            "error_message": str(e)
        }
```

## 🚨 Troubleshooting

### **Common Issues & Solutions**

**❌ Import Error: No module named 'google.adk'**
```bash
# Solution: Install Google ADK
uv pip install google-adk
```

**❌ API Key Missing or Invalid**
```bash
# Check .env file
cat .env
# Verify API key format and permissions
```

**❌ MCP Connection Failed**
```bash
# Check Node.js installation
node --version  # Should be v16+

# Reinstall MCP packages
npm install -g @modelcontextprotocol/server-filesystem
```

**❌ Permission Denied (MCP Filesystem)**
```bash
# Fix directory permissions
chmod 755 /path/to/directory
```

**❌ Port Already in Use**
```bash
# Kill existing process
lsof -ti:8000 | xargs kill -9

# Or use different port
adk web --app_name agent_name --port 8001
```

### **Debug Tips**

1. **Check Logs**: Look at terminal output for error details
2. **Test API Keys**: Use curl or Postman to verify API access
3. **Verify Environment**: Ensure all environment variables are set
4. **Browser Console**: Check for JavaScript errors
5. **Network Issues**: Verify internet connection for API calls

## 📚 Resources & Documentation

### **Official Documentation**
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [ADK Quickstart Guide](https://google.github.io/adk-docs/get-started/quickstart/)
- [Model Context Protocol](https://modelcontextprotocol.io/)

### **API Documentation**
- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [Shodan API](https://developer.shodan.io/)
- [OpenWeatherMap API](https://openweathermap.org/api)
- [Google AI API](https://ai.google.dev/docs)

### **MCP Resources**
- [MCP Servers Collection](https://github.com/punkpeye/awesome-mcp-servers)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)


