import json
from typing import Dict, Any
from rich.console import Console

from src.ai.ai_service import AIService
from src.ai.system.prompt_config import PromptConfig

console = Console()

class VisionAnalyzer:    
    def __init__(self):
        self.llm_client = AIService()
        self.prompt_config = PromptConfig(promptfile="browser_prompts.yaml")
    
    async def analyze_screenshot(self, screenshot_b64: str, task: str, page_info: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # Prepare the vision prompt
            system_prompt = self._get_system_prompt()
            user_prompt = self._get_user_prompt(task, page_info)
            messages=[
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user", 
                        "content": [
                            {"type": "text", "text": user_prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{screenshot_b64}"
                                }
                            }
                        ]
                    }
                ]
            response = await self.llm_client.vision_generate(messages)
            result = self._parse_response(response)

            # console.log(f"Vision analysis completed for task: {task}")
            return result
            
        except Exception as e:
            console.log(f"Failed to analyze screenshot: {e}")
            return self._get_error_action(str(e))
    
    def _get_system_prompt(self) -> str:
        return self.prompt_config.get("visionSystemPrompt")

    def _get_user_prompt(self, task: str, page_info: Dict[str, Any]) -> str:
        return self.prompt_config.get_with_values("visionUserPrompt", {
            "task": task,
            "url": str(page_info.get("url", "Unknown")),
            "title": str(page_info.get("title", "Unknown")),
            "viewport": str(page_info.get("viewport", "Unknown"))
        })
    
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the AI response into a structured action"""
        try:
            # Try to extract JSON from the response
            response_text = response_text.strip()
            
            # Find JSON in the response (handle cases where it's wrapped in markdown)
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response_text[start_idx:end_idx]
                result = json.loads(json_str)
                
                # Validate required fields
                if 'action' not in result:
                    result['action'] = 'error'
                    result['message'] = 'Invalid response format: missing action'
                
                return result
            else:
                console.log("Could not find JSON in response")
                return self._get_error_action("Could not parse AI response")
                
        except json.JSONDecodeError as e:
            console.log(f"Failed to parse JSON response: {e}")
            return self._get_error_action(f"JSON parsing error: {e}")
        except Exception as e:
            console.log(f"Unexpected error parsing response: {e}")
            return self._get_error_action(f"Response parsing error: {e}")
    
    def _get_error_action(self, error_message: str) -> Dict[str, Any]:
        """Generate an error action response"""
        return {
            "action": "error",
            "reasoning": f"Error occurred: {error_message}",
            "success": False,
            "message": error_message
        }

    async def validate_completion(self, screenshot_b64: str, task: str, page_info: Dict[str, Any]) -> bool:
        try:
            validation_prompt = self.prompt_config.get_with_values("visionValidationPrompt", {
                "task": task,
                "url": page_info.get("url", "Unknown"),
                "title": page_info.get("title", "Unknown"),
                "viewport": page_info.get("viewport", "Unknown")
            })
            messages = [{
                        "role": "user", 
                        "content": [
                            {"type": "text", "text": validation_prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{screenshot_b64}"
                                }
                            }
                        ]
                    }]
            response = await self.llm_client.vision_generate(
                messages=messages,
                max_tokens=10
            )
            result = response.strip().upper()
            
            return result.startswith('YES')
            
        except Exception as e:
            console.log(f"Failed to validate completion: {e}")
            return False
