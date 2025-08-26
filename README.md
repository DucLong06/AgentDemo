# ADK Agent Development Project

A collection of intelligent agents built with Google's Agent Development Kit (ADK), featuring security analysis, MCP integrations, and sequential processing pipelines.

## Project Structure

```
AgentDemo/
├── agent_mcp/              # Basic MCP integration example
├── agent_security/         # Security-focused code analysis agent
├── agent_time_weather/     # Time and weather information agent
├── agent_virus_mcp/        # VirusTotal MCP integration
├── Sequential_agents/      # Basic sequential agent pipeline
├── Sequential_agents_mcp/  # Sequential pipeline with MCP security tools
├── dockerfile              # Docker container setup
├── docker-compose.yaml     # Container orchestration
└── README.md              # This file
```

## Quick Start (Docker - Recommended)

### 1. Run with Docker Compose
```bash
# Clone or navigate to project directory
cd AgentDemo

# Start all services
docker-compose up --build

# Run in background
docker-compose up -d --build

# Access the web interface
open http://localhost:8000
```

### 2. Using Individual Agents

Once the container is running, you can access different agents through the web interface:

- **Sequential_agents**: Basic code writing → review → refactoring pipeline
- **Sequential_agents_mcp**: Enhanced pipeline with Semgrep security analysis
- **agent_security**: Specialized security code review agent
- **agent_virus_mcp**: File and URL security scanning via VirusTotal
- **agent_time_weather**: Time and weather information utilities

## Alternative Setup (Manual Installation)

### Prerequisites
```bash
# Install Python 3.11+
python --version

# Install ADK
pip install google-adk python-dotenv mcp

# Optional: Install security tools
pip install uv
uv tool install semgrep-mcp
```

### Run Agents
```bash
# Navigate to project directory
cd AgentDemo

# Start ADK web interface
adk web --host 0.0.0.0 --port 8000

# Access at http://localhost:8000
```

## Agent Capabilities

### Security Analysis Pipeline (Sequential_agents_mcp)
- **Code Generation**: Creates Python code from requirements
- **Security Scanning**: Uses Semgrep MCP for vulnerability detection
- **Code Review**: Identifies security issues, code quality problems
- **Automated Fixes**: Refactors code to resolve identified issues

**Detects**: SQL injection, XSS, command injection, hard-coded secrets, path traversal, and 5,000+ other security patterns.

### VirusTotal Integration (agent_virus_mcp)
- **File Scanning**: Upload files for malware analysis
- **URL Checking**: Verify website safety and reputation
- **IP Analysis**: Check IP addresses against threat databases
- **Domain Reports**: Comprehensive domain security information

### Basic Utilities
- **Weather Agent**: Current weather and forecasts
- **Time Agent**: Time zone conversions and scheduling
- **Security Agent**: General security best practices review

## Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
GOOGLE_API_KEY=your_api_key_here
GOOGLE_GENAI_USE_VERTEXAI=FALSE

# Optional: Semgrep App Token for enhanced features
SEMGREP_APP_TOKEN=your_token_here

# Optional: VirusTotal API Key
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Docker Environment
The Docker setup automatically configures:
- Python 3.11 runtime
- Node.js for MCP server support
- ADK framework and dependencies
- Semgrep MCP tools via uvx
- All required system dependencies

## Usage Examples

### Test Security Analysis
Try this prompt with Sequential_agents_mcp:

```
Create a Python Flask web application with user login that:
1. Connects to MySQL database with hardcoded password
2. Accepts username/password and queries database directly  
3. Has file upload functionality
4. Includes API keys in source code
5. Runs system commands based on user input
```

Expected output: Detection of SQL injection, hard-coded credentials, command injection, and secure refactored code.

### Test VirusTotal Integration
Use agent_virus_mcp to:
- Upload suspicious files for analysis
- Check URLs before visiting
- Verify IP addresses and domains
- Get comprehensive threat intelligence reports

## Development

### Adding New Agents
1. Create new directory: `agent_name/`
2. Add `agent.py` with root_agent definition
3. Restart Docker container or ADK service
4. Agent appears in web interface automatically

### MCP Integration
Agents support Model Context Protocol for external tool integration:
- Semgrep for security analysis
- VirusTotal for threat detection
- Custom MCP servers via SSE or stdio

### Debugging
```bash
# View container logs
docker-compose logs -f

# Access container shell
docker exec -it adk-dev bash

# Check MCP tools
uvx semgrep-mcp --help

# Test connections
curl https://mcp.semgrep.ai/sse
```

## Troubleshooting

### Common Issues

**Port 8000 already in use:**
```bash
# Change port in docker-compose.yaml
ports:
  - "8001:8000"
```

**MCP tools not working:**
```bash
# Rebuild container with clean cache
docker-compose down
docker-compose up --build --force-recreate
```

**Agent not found:**
```bash
# Ensure agent.py has root_agent defined
# Check file structure matches expected format
# Verify container volume mounts
```

### Performance Tips
- Use `.dockerignore` to exclude unnecessary files
- Mount only required directories in docker-compose
- Enable MCP_DEBUG=true for connection troubleshooting
- Monitor container resource usage for large projects

## Security Features

### Built-in Protections
- Container isolation for MCP server processes
- Environment variable management for API keys
- Network restrictions for external MCP connections
- Input validation and sanitization in agents

### Security Analysis Capabilities
- **Static Analysis**: 5,000+ Semgrep security rules
- **Vulnerability Detection**: CWE-mapped security issues
- **Code Quality**: PEP 8 compliance and best practices
- **Threat Intelligence**: VirusTotal integration for files/URLs

## Support

- **ADK Documentation**: https://google.github.io/adk-docs/
- **Semgrep Rules**: https://semgrep.dev/r
- **MCP Protocol**: https://spec.modelcontextprotocol.io/
- **Issues**: Create issues for bugs or feature requests

---

**Quick Commands Reference:**
```bash
# Start development environment
docker-compose up -d

# Access web UI
open http://localhost:8000

# View logs
docker-compose logs -f

# Stop services  
docker-compose down
```