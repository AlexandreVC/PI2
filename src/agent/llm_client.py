"""LLM Client for interacting with AI models."""

import json
import logging
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    model: str
    tokens_used: int = 0
    response_time_sec: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    def generate(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            temperature: float = 0.0,
            max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate a response from the LLM."""
        pass


class OllamaClient(BaseLLMClient):
    """Client for Ollama API."""

    def __init__(
            self,
            base_url: str = "http://localhost:11434",
            model: str = "gpt-oss:20b",
            timeout: int = 600
    ):
        """
        Initialize Ollama client.

        Args:
            base_url: Ollama API base URL
            model: Default model to use
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout

    def generate(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            temperature: float = 0.0,
            max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate response using Ollama API."""
        import time

        if not HAS_REQUESTS:
            return self._mock_response(prompt)

        start_time = time.time()

        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            content = data.get("message", {}).get("content", "")

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=data.get("eval_count", 0),
                response_time_sec=time.time() - start_time,
                raw_response=data
            )

        except requests.RequestException as e:
            logger.error(f"Ollama API error: {e}")
            return self._mock_response(prompt)

    def _mock_response(self, prompt: str) -> LLMResponse:
        """Generate mock response when API is unavailable."""
        logger.warning("Using mock response (API unavailable)")

        # Generate contextual mock response based on prompt
        if "vulnerability" in prompt.lower() or "cve" in prompt.lower():
            content = self._mock_vulnerability_analysis()
        elif "remediation" in prompt.lower():
            content = self._mock_remediation()
        elif "risk" in prompt.lower():
            content = self._mock_risk_assessment()
        else:
            content = "Analysis completed. Please review the findings."

        return LLMResponse(
            content=content,
            model="mock",
            tokens_used=len(content.split()),
            response_time_sec=0.1
        )

    def _mock_vulnerability_analysis(self) -> str:
        return """## Vulnerability Analysis

### Summary
This vulnerability allows remote attackers to execute arbitrary code on affected systems.

### Technical Details
- **Attack Vector**: Network-based
- **Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None

### Impact
- Confidentiality: HIGH - Complete system compromise possible
- Integrity: HIGH - Arbitrary code execution
- Availability: HIGH - System denial of service

### Recommendations
1. Apply vendor patches immediately
2. Implement network segmentation
3. Enable intrusion detection
4. Monitor for exploitation attempts"""

    def _mock_remediation(self) -> str:
        return """## Remediation Plan

### Immediate Actions (24-48 hours)
1. **Patch Application**: Apply security updates from vendor
2. **Temporary Mitigation**: Implement firewall rules to restrict access

### Short-term Actions (1-2 weeks)
1. Review and harden configurations
2. Implement additional monitoring
3. Conduct security assessment

### Long-term Actions (1-3 months)
1. Architecture review
2. Security training
3. Implement defense-in-depth strategy"""

    def _mock_risk_assessment(self) -> str:
        return """## Risk Assessment

### Risk Level: HIGH

### Business Impact
- **Operational**: Critical services may be disrupted
- **Financial**: Potential data breach costs
- **Reputational**: Customer trust impact

### Likelihood: HIGH
- Exploit publicly available
- Low complexity to exploit
- No authentication required

### Priority: P1 - Critical
Immediate remediation required within 24 hours."""


class OpenAIClient(BaseLLMClient):
    """Client for OpenAI-compatible APIs."""

    def __init__(
            self,
            api_key: str,
            base_url: str = "https://api.openai.com/v1",
            model: str = "gpt-4",
            timeout: int = 600
    ):
        """Initialize OpenAI client."""
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout

    def generate(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            temperature: float = 0.0,
            max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate response using OpenAI API."""
        import time

        if not HAS_REQUESTS:
            return LLMResponse(
                content="API unavailable",
                model=self.model,
                tokens_used=0,
                response_time_sec=0
            )

        start_time = time.time()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            content = data["choices"][0]["message"]["content"]

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=data.get("usage", {}).get("total_tokens", 0),
                response_time_sec=time.time() - start_time,
                raw_response=data
            )

        except requests.RequestException as e:
            logger.error(f"OpenAI API error: {e}")
            return LLMResponse(
                content=f"Error: {e}",
                model=self.model,
                tokens_used=0,
                response_time_sec=time.time() - start_time
            )


class LLMClient:
    """
    Unified LLM client that supports multiple backends.

    Supports: Ollama, OpenAI, and compatible APIs.
    """

    def __init__(
            self,
            api_type: str = "ollama",
            model: str = "gpt-oss:20b",
            api_key: Optional[str] = None,
            base_url: Optional[str] = None,
            timeout: int = 600
    ):
        """
        Initialize LLM client.

        Args:
            api_type: Type of API ("ollama", "openai")
            model: Model identifier
            api_key: API key (required for OpenAI)
            base_url: Custom API base URL
            timeout: Request timeout
        """
        self.api_type = api_type
        self.model = model

        if api_type == "ollama":
            base_url = base_url or "http://localhost:11434"
            self._client = OllamaClient(base_url, model, timeout)
        elif api_type == "openai":
            base_url = base_url or "https://api.openai.com/v1"
            self._client = OpenAIClient(api_key, base_url, model, timeout)
        else:
            # Default to Ollama
            self._client = OllamaClient(
                base_url or "http://localhost:11434",
                model,
                timeout
            )

    def generate(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            temperature: float = 0.0,
            max_tokens: int = 4096
    ) -> LLMResponse:
        """Generate a response."""
        return self._client.generate(prompt, system_prompt, temperature, max_tokens)

    def generate_json(
            self,
            prompt: str,
            system_prompt: Optional[str] = None,
            temperature: float = 0.0,
            max_tokens: int = 4096,
            retry_count: int = 3
    ) -> Dict[str, Any]:
        """
        Generate a JSON response with retry mechanism.

        Implements the "Retry with Regex fallback" pattern from project specs.
        """
        # Add JSON instruction to prompt
        json_prompt = f"{prompt}\n\nRespond with valid JSON only. No markdown, no explanation."

        for attempt in range(retry_count):
            response = self.generate(json_prompt, system_prompt, temperature, max_tokens)

            try:
                # Try direct JSON parse
                return json.loads(response.content)
            except json.JSONDecodeError:
                # Attempt regex extraction
                json_match = re.search(r'\{[\s\S]*\}', response.content)
                if json_match:
                    try:
                        return json.loads(json_match.group())
                    except json.JSONDecodeError:
                        pass

                # Try array format
                array_match = re.search(r'\[[\s\S]*\]', response.content)
                if array_match:
                    try:
                        return {"data": json.loads(array_match.group())}
                    except json.JSONDecodeError:
                        pass

                logger.warning(f"JSON parse attempt {attempt + 1} failed")

        # Return empty dict on failure
        logger.error("Failed to parse JSON after all attempts")
        return {}

    def switch_model(self, model: str):
        """Switch to a different model."""
        self.model = model
        if isinstance(self._client, OllamaClient):
            self._client.model = model
        elif isinstance(self._client, OpenAIClient):
            self._client.model = model
