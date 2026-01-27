# AI Assistant Integration Guide

## 🤖 Overview

The vulnerability scanner includes a flexible AI assistant that supports multiple AI providers. Users can configure their preferred AI service to get intelligent vulnerability analysis, remediation advice, and learning recommendations.

## 🎯 Supported Providers

| Provider | Type | Cost | Privacy | Setup Difficulty |
|----------|------|------|---------|------------------|
| **OpenAI (GPT-4)** | Cloud | $$ | Shared | Easy |
| **Anthropic (Claude)** | Cloud | $$ | Shared | Easy |
| **Google (Gemini)** | Cloud | $ | Shared | Easy |
| **Ollama** | Local | Free | Private | Medium |
| **Custom API** | Any | Varies | Varies | Advanced |

## 🔧 Configuration

### Via Settings UI

1. Navigate to **Settings** → **AI Assistant**
2. Enable AI Assistant
3. Select your provider
4. Enter API key (if required)
5. Configure model and base URL
6. Test connection
7. Save settings

### Via Environment Variables

```bash
# .env file
AI_ENABLED=true
AI_PROVIDER=openai
AI_API_KEY=sk-...
AI_MODEL=gpt-4
AI_BASE_URL=  # Optional, for custom endpoints
```

## 📚 Provider Setup Guides

### OpenAI (GPT-4)

1. **Get API Key**: https://platform.openai.com/api-keys
2. **Provider**: Select "OpenAI (GPT-4)"
3. **API Key**: Paste your key (starts with `sk-`)
4. **Model**: `gpt-4` or `gpt-4-turbo`
5. **Cost**: ~$0.03 per 1K tokens (input), ~$0.06 per 1K tokens (output)

**Recommended for**: Best quality analysis, detailed explanations

### Anthropic (Claude)

1. **Get API Key**: https://console.anthropic.com/
2. **Provider**: Select "Anthropic (Claude)"
3. **API Key**: Paste your key
4. **Model**: `claude-3-5-sonnet-20241022`
5. **Cost**: ~$0.003 per 1K tokens (input), ~$0.015 per 1K tokens (output)

**Recommended for**: Long context analysis, detailed remediation

### Google (Gemini)

1. **Get API Key**: https://makersuite.google.com/app/apikey
2. **Provider**: Select "Google (Gemini)"
3. **API Key**: Paste your key
4. **Model**: `gemini-pro`
5. **Cost**: Free tier available, then $0.00025 per 1K characters

**Recommended for**: Budget-conscious users, free tier

### Ollama (Local)

1. **Install Ollama**: https://ollama.ai/download
2. **Pull Model**: `ollama pull llama2`
3. **Provider**: Select "Ollama (Local)"
4. **Base URL**: `http://localhost:11434/api/generate`
5. **Model**: `llama2`, `mistral`, `codellama`, etc.
6. **Cost**: Free (runs on your hardware)

**Recommended for**: Privacy-focused users, offline usage

**System Requirements**:
- 8GB RAM minimum (16GB recommended)
- GPU optional but recommended
- ~4GB disk space per model

### Custom API

For self-hosted or custom AI endpoints:

1. **Provider**: Select "Custom API"
2. **Base URL**: Your API endpoint
3. **API Key**: Your authentication key
4. **Request Format**: Must accept `{"prompt": "..."}`
5. **Response Format**: JSON with analysis fields

## 🎨 AI Features

### 1. Vulnerability Analysis

Get plain English explanations of findings:

```python
{
  "explanation": "This SQL injection allows attackers to...",
  "risk_assessment": "Critical - Could expose entire database",
  "exploitation_scenario": "Attacker could use UNION queries to...",
  "remediation_priority": "Critical - Fix immediately"
}
```

### 2. Custom Remediation

Tech-stack specific fix suggestions:

```python
# Input: Finding + Tech Stack (Python, Django, PostgreSQL)
{
  "code_fix": "Use Django ORM or parameterized queries...",
  "configuration_changes": "Update settings.py...",
  "best_practices": ["Use ORM", "Validate inputs"],
  "testing_steps": ["Test with SQLMap", "Code review"]
}
```

### 3. Learning Recommendations

Personalized learning paths:

```python
{
  "learning_path": [
    "PortSwigger SQL Injection tutorial",
    "OWASP Testing Guide",
    "SQLi Labs practice"
  ],
  "practice_labs": ["SQLi Labs", "HackTheBox"],
  "estimated_time": "2-3 weeks",
  "key_concepts": ["SQL syntax", "UNION attacks"],
  "pitfalls": ["Forgetting to encode", "Missing edge cases"]
}
```

### 4. Audience-Specific Explanations

Explain findings to different audiences:

- **Technical**: Detailed technical analysis
- **Executive**: Business impact focus
- **Beginner**: Simple, jargon-free explanations

## 💡 Usage Examples

### In Results Page

When viewing a finding, click **"Ask AI"** to get:
- Plain English explanation
- Risk assessment
- Exploitation scenario
- Fix recommendations

### In Knowledge Base

Click **"Get Learning Path"** to receive:
- Personalized tutorials
- Practice labs
- Estimated learning time
- Key concepts to master

### In Scan Configuration

Enable **"AI-Enhanced Scanning"** for:
- Automatic finding analysis
- Priority recommendations
- Context-aware remediation

## 🔒 Privacy & Security

### Data Handling

- **API Keys**: Encrypted at rest, never logged
- **Findings**: Sent to AI provider for analysis
- **Local Mode**: Use Ollama for complete privacy

### Best Practices

1. **Use Ollama** for sensitive projects
2. **Review prompts** before sending to cloud APIs
3. **Rotate API keys** regularly
4. **Monitor usage** to avoid unexpected costs
5. **Sanitize data** before AI analysis

## 💰 Cost Estimation

### Typical Usage (per scan)

| Provider | Findings | Cost per Scan | Monthly (30 scans) |
|----------|----------|---------------|-------------------|
| OpenAI GPT-4 | 10 findings | ~$0.50 | ~$15 |
| Anthropic Claude | 10 findings | ~$0.20 | ~$6 |
| Google Gemini | 10 findings | ~$0.05 | ~$1.50 |
| Ollama | Unlimited | $0 | $0 |

**Note**: Costs vary based on finding complexity and analysis depth.

## 🛠️ Troubleshooting

### Connection Failed

**OpenAI/Anthropic/Google**:
- Verify API key is correct
- Check API key has credits
- Ensure network connectivity
- Verify API endpoint is accessible

**Ollama**:
- Ensure Ollama is running: `ollama serve`
- Check model is pulled: `ollama list`
- Verify base URL is correct
- Check firewall settings

### Slow Responses

- Use faster models (gpt-3.5-turbo vs gpt-4)
- Reduce analysis depth
- Use local Ollama for instant responses
- Check network latency

### Poor Quality Analysis

- Use more advanced models (GPT-4, Claude 3.5)
- Provide more context in findings
- Specify tech stack for better remediation
- Adjust temperature settings

## 📊 Comparison Matrix

| Feature | OpenAI | Anthropic | Google | Ollama |
|---------|--------|-----------|--------|--------|
| Quality | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| Speed | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Cost | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Privacy | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Setup | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

## 🚀 Advanced Configuration

### Custom Prompts

Edit `scanner-core/ai/assistant.py` to customize prompts:

```python
def _build_vulnerability_prompt(self, finding):
    return f"""
    Custom prompt template here...
    {finding.get('name')}
    """
```

### Rate Limiting

Configure rate limits in settings:

```python
AI_RATE_LIMIT = 10  # requests per minute
AI_MAX_TOKENS = 2048
AI_TEMPERATURE = 0.7
```

### Caching

Enable response caching to reduce costs:

```python
AI_CACHE_ENABLED = True
AI_CACHE_TTL = 3600  # 1 hour
```

---

**Need Help?** Check the [FAQ](./FAQ.md) or open an issue on GitHub.
