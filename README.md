# BurpAI Chat Plugin

BurpAI Chat is a powerful Burp Suite extension that integrates AI-assisted analysis into your web application security testing workflow. This plugin allows security professionals to leverage the capabilities of large language models to analyze HTTP requests and responses, providing insights and assistance during penetration testing and vulnerability assessment tasks.

## Features

- **AI-Powered Analysis**: Interact with OpenAI's GPT models to analyze selected HTTP requests and responses.
- **Request Selection**: Choose multiple requests from Burp Suite to send for AI analysis.
- **Request/Response Viewer**: Built-in viewer for inspecting selected HTTP requests and responses.
- **Configurable AI Provider**: Support for OpenAI, with planned support for Anthropic's Claude.
- **Model Selection**: Choose between different AI models (e.g., GPT-4, GPT-3.5-Turbo).
- **Data Obfuscation**: Option to obfuscate sensitive data such as hostnames and URLs before sending to the AI service.
- **Custom Prompts**: Enter custom questions or prompts for the AI to analyze the selected requests.
- **User-Friendly Interface**: Intuitive GUI with split panes for easy navigation and interaction.
- **API Key Management**: Securely input and optionally save your API key for the AI service.
- **Context Menu Integration**: Easily send requests to BurpAI Chat from Burp Suite's standard interfaces.

## How It Works

1. Select one or more HTTP requests from any Burp Suite tool.
2. Send the selected requests to the BurpAI Chat tab using the context menu.
3. Configure the AI provider, model, and other settings in the BurpAI Chat tab.
4. Enter a custom prompt or question for the AI to analyze.
5. Click "Send to AI Chat" to receive AI-generated insights about the selected requests.

## Installation

1. Ensure you have Jython set up in Burp Suite.
2. Load the `burp-chat-plugin.py` script as a Burp Suite extension.
3. The "BurpAI Chat" tab will appear in the Burp Suite interface.

## Configuration

- Enter your OpenAI API key in the provided field.
- Select the AI provider and model from the dropdown menus.
- Optionally enable data obfuscation to protect sensitive information.

## Usage

1. Capture traffic or select existing requests in Burp Suite.
2. Right-click on the desired requests and choose "Send to BurpAI Chat".
3. In the BurpAI Chat tab, review the selected requests in the table.
4. Enter your question or prompt in the "Question to AI" text area.
5. Click "Send to AI Chat" to receive the AI's analysis.
6. View the AI's response in the "AI Response" text area.

## Security Considerations

- The plugin sends selected HTTP data to external AI services. Use with caution and in compliance with your organization's security policies.
- Enable the data obfuscation option when working with sensitive information.
- Ensure your API key is kept secure and not shared.

## Contributing

Contributions to improve BurpAI Chat are welcome. Please submit pull requests or open issues on the project's GitHub repository.



## Disclaimer

This tool is for educational and professional use in authorized security testing only. The developers are not responsible for any misuse or damage caused by this tool.
# Example

![Exmaple Photo](./2023-04-11_09-14.png)

