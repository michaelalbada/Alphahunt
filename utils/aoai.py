import os
import time
from openai import AzureOpenAI
from termcolor import colored
import json
from azure.identity import DefaultAzureCredential, get_bearer_token_provider

token_provider = get_bearer_token_provider(
    DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
)

endpoint = 'https://devpythiaaoaieus.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2023-03-15-preview'

endpoint1 = "https://medeina-openai-dev-011.openai.azure.com/"

client = AzureOpenAI(
  azure_endpoint = endpoint, 
  azure_ad_token_provider=token_provider,  
  api_version="2024-02-15-preview"
)


def create_open_ai_client():
    token_provider = get_bearer_token_provider(
        DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
    )

    client = AzureOpenAI(
        azure_endpoint = endpoint, 
        azure_ad_token_provider=token_provider,  
        api_version="2024-02-15-preview"
    )
    return client

class LLM:
    def __init__(self, model_name, verbose=False):
        self.model_name = model_name
        self.verbose = verbose
        self.count = 0
        self.error_count = 0
        self.context_length = 4000

        self.client = create_open_ai_client()
        self.context_length = 128 * 1000

    def __call__(self, message, *args, **kwargs):
        # Trim message content to context length
        for i, m in enumerate(message):
            message[i]["content"] = message[i]["content"][:self.context_length]

        if self.verbose:
            # Message is a list of dictionaries with role and content keys.
            # Color each role differently.
            for m in message:
                if m["role"] == "user":
                    print(colored(f"{m['content']}\n", "cyan"))
                elif m["role"] == "assistant":
                    print(colored(f"{m['content']}\n", "green"))
                elif m["role"] == "system":
                    print(colored(f"{m['content']}\n", "yellow"))
                else:
                    print(colored(f"Unknown role: {m['content']}\n", "red"))

        self.count += 1
        while True:
            try:
                return_response = self.client.chat.completions.create(model = self.model_name, messages = message).choices[0].message.content
                break

            except Exception as e:
                print(colored(f"Error: {e}", "red"))
                self.error_count += 1
                time.sleep(10 * self.error_count)
                if self.error_count > 1000:
                    raise Exception("Too many errors, exiting)")

        if self.count % 100 == 0:
            time.sleep(10)

        if self.verbose:
            print(colored(return_response, "green"))

        return return_response
    
if __name__ == '__main__':
    client = create_open_ai_client()
    print(client.chat.completions.create(model = 'gpt-4o-0806', messages = [{"role": "user", 'content': "tell me a joke"}]).choices[0].message.content)
