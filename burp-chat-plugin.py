# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from java.awt import BorderLayout, FlowLayout, GridLayout
from javax.swing import (JPanel, JButton, JScrollPane, JTable,
                         ListSelectionModel, JLabel, JTextField,
                         JComboBox, JCheckBox, JMenuItem, JOptionPane, JSplitPane, JTabbedPane, JTextArea, ImageIcon)
from javax.swing.table import DefaultTableModel
from javax.swing.border import EmptyBorder, TitledBorder
from java.awt.event import ActionListener
from java.net import URL, HttpURLConnection
from javax.net.ssl import HttpsURLConnection, SSLContext, TrustManager, X509TrustManager
from java.security import SecureRandom
from java.io import BufferedReader, InputStreamReader
from java.lang import StringBuilder
from java.util import Random
import json, base64, re, ssl


# Create a trust manager that does not validate certificate chains
class TrustAllX509TrustManager(X509TrustManager):
    def checkClientTrusted(self, chain, auth_type):
        pass

    def checkServerTrusted(self, chain, auth_type):
        pass

    def getAcceptedIssuers(self):
        return None

# Install the all-trusting trust manager
trust_all_certs = [TrustAllX509TrustManager()]
sc = SSLContext.getInstance("TLS")
sc.init(None, trust_all_certs, SecureRandom())
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self._obfuscation_map = {}
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpAI Chat")

        # Initialize Random instance
        self._random_generator = Random()

        self.init_gui()

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def init_gui(self):
        # Main panel with modern design
        self._main_panel = JPanel()
        self._main_panel.setLayout(BorderLayout())
        self._main_panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Configuration panel
        config_panel = JPanel()
        config_panel.setLayout(GridLayout(3, 1, 10, 10))
        config_panel.setBorder(TitledBorder("Configuration"))

        # API Key panel
        api_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._api_key_label = JLabel("API Key:")
        self._api_key_field = JTextField(30)
        self._save_api_key = JCheckBox("Save API Key")
        api_panel.add(self._api_key_label)
        api_panel.add(self._api_key_field)
        api_panel.add(self._save_api_key)

        # AI Provider and Model selection panel
        ai_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._ai_provider = JComboBox(["OpenAI", "Claude"])
        self._ai_provider.setSelectedItem("OpenAI")
        self._model_selector = JComboBox(["gpt-4o", "gpt-4o-mini"])
        self._model_selector.setSelectedItem("gpt-4o-mini")
        ai_panel.add(JLabel("AI Provider:"))
        ai_panel.add(self._ai_provider)
        ai_panel.add(JLabel("Model:"))
        ai_panel.add(self._model_selector)

        # Obfuscate Data option
        obfuscate_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._obfuscate_checkbox = JCheckBox("Obfuscate Data")
        self._obfuscate_checkbox.setToolTipText("When selected, URLs (excluding paths) and hosts will be replaced with random text before being sent to the AI.")
        obfuscate_panel.add(self._obfuscate_checkbox)
        # Add a question mark icon with tooltip
        info_icon = ImageIcon()
        info_label = JLabel("?", info_icon, JLabel.CENTER)
        info_label.setToolTipText("Obfuscate Data replaces all URLs (excluding paths) and hosts with random text before sending to the AI.")
        obfuscate_panel.add(info_label)

        config_panel.add(api_panel)
        config_panel.add(ai_panel)
        config_panel.add(obfuscate_panel)

        # Button panel
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        self._send_button = JButton("Send to AI Chat", actionPerformed=self.send_to_ai_chat)
        self._clear_button = JButton("Clear Requests", actionPerformed=self.clear_requests)
        button_panel.add(self._send_button)
        button_panel.add(self._clear_button)

        # Left panel with table and request/response preview
        left_panel = JPanel()
        left_panel.setLayout(BorderLayout(10, 10))

        # Requests table
        table_panel = JPanel()
        table_panel.setLayout(BorderLayout())
        table_panel.setBorder(TitledBorder("Selected Requests"))

        column_names = ["#", "Method", "URL"]
        self._table_model = DefaultTableModel(column_names, 0)
        self._request_table = JTable(self._table_model)
        # Allow multiple selection
        self._request_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._request_table.getSelectionModel().addListSelectionListener(self.update_preview)
        table_scroll = JScrollPane(self._request_table)
        table_panel.add(table_scroll, BorderLayout.CENTER)

        # Request and Response preview using Burp's IMessageEditor
        self._request_viewer = self._callbacks.createMessageEditor(self, False)
        self._response_viewer = self._callbacks.createMessageEditor(self, False)

        # Create the tabbed pane using JTabbedPane
        preview_tabs = JTabbedPane()
        preview_tabs.addTab("Request", self._request_viewer.getComponent())
        preview_tabs.addTab("Response", self._response_viewer.getComponent())

        # Split pane for table and previews
        left_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        left_split.setTopComponent(table_panel)
        left_split.setBottomComponent(preview_tabs)
        left_split.setDividerLocation(200)

        left_panel.add(left_split, BorderLayout.CENTER)

        # Right panel with AI interaction
        right_panel = JPanel()
        right_panel.setLayout(BorderLayout(10, 10))

        # Split pane for Question and AI Response
        ai_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        ai_split_pane.setDividerLocation(150)

        # Question to AI panel
        system_panel = JPanel(BorderLayout())
        system_panel.setBorder(TitledBorder("Question to AI"))
        self._system_area = JTextArea(5, 50)
        system_panel.add(JScrollPane(self._system_area), BorderLayout.CENTER)
        ai_split_pane.setTopComponent(system_panel)

        # AI Response panel
        chat_panel = JPanel(BorderLayout())
        chat_panel.setBorder(TitledBorder("AI Response"))
        self._chat_area = JTextArea()
        chat_panel.add(JScrollPane(self._chat_area), BorderLayout.CENTER)
        ai_split_pane.setBottomComponent(chat_panel)

        right_panel.add(ai_split_pane, BorderLayout.CENTER)

        # Main split pane dividing left and right panels
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        main_split.setLeftComponent(left_panel)
        main_split.setRightComponent(right_panel)
        main_split.setDividerLocation(600)

        # Adding components to the main panel
        top_panel = JPanel()
        top_panel.setLayout(BorderLayout())
        top_panel.add(config_panel, BorderLayout.CENTER)
        top_panel.add(button_panel, BorderLayout.SOUTH)

        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(main_split, BorderLayout.CENTER)

        # Initialize lists to store request/response data
        self._request_responses = []

    def createMenuItems(self, invocation):
        menu = []
        messages = invocation.getSelectedMessages()
        if messages:
            menu_item = JMenuItem("Send to BurpAI Chat", actionPerformed=lambda x, inv=invocation: self.add_requests_to_table(inv))
            menu.append(menu_item)
        return menu

    def add_requests_to_table(self, invocation):
        messages = invocation.getSelectedMessages()
        for messageInfo in messages:
            request = self._helpers.analyzeRequest(messageInfo)
            url = request.getUrl().toString()
            method = request.getMethod()

            row_data = [self._table_model.getRowCount() + 1, method, url]
            self._table_model.addRow(row_data)

            # Store IHttpRequestResponse for later use
            self._request_responses.append(messageInfo)
        JOptionPane.showMessageDialog(None, "Requests added to BurpAI Chat.")

    def update_preview(self, event):
        if not event.getValueIsAdjusting():
            selected_rows = self._request_table.getSelectedRows()
            if len(selected_rows) >= 1:
                # Show the last selected request
                selected_row = selected_rows[-1]
                message_info = self._request_responses[selected_row]
                self._currently_displayed_item = message_info
                self._request_viewer.setMessage(message_info.getRequest(), True)
                if message_info.getResponse():
                    self._response_viewer.setMessage(message_info.getResponse(), False)
                else:
                    self._response_viewer.setMessage(None, False)
            else:
                self._request_viewer.setMessage(None, True)
                self._response_viewer.setMessage(None, False)

    # Implement IMessageEditorController interface methods
    def getHttpService(self):
        return self._currently_displayed_item.getHttpService()

    def getRequest(self):
        return self._currently_displayed_item.getRequest()

    def getResponse(self):
        return self._currently_displayed_item.getResponse()

    def send_to_ai_chat(self, event):
        selected_rows = self._request_table.getSelectedRows()
        if len(selected_rows) > 0:
            messages = [{"role": "system", "content": u"You are a pentester assistant. You receive JSON data from different URLs.   You just have to answer in the best possible way (it doesn't always have to be long, you have to be precise) what you are asked for in question."}]
            question = self._system_area.getText()

            obfuscate = self._obfuscate_checkbox.isSelected()

            for idx in selected_rows:
                message_info = self._request_responses[idx]
                request_bytes = message_info.getRequest()
                response_bytes = message_info.getResponse() if message_info.getResponse() else b""
                request_content = self._helpers.bytesToString(request_bytes)
                response_content = self._helpers.bytesToString(response_bytes)
                method = self._table_model.getValueAt(idx, 1)
                url = self._table_model.getValueAt(idx, 2)

                if obfuscate:
                    url = self.obfuscate_url(url)
                    request_content = self.obfuscate_hosts_in_request(request_content)
                    response_content = self.obfuscate_hosts_in_response(response_content)

                content_json = {
                    "url": url,
                    "method": method,
                    "request": request_content,  # Texto plano
                    "response": response_content  # Texto plano
                }
                messages.append({"role": "user", "content": json.dumps(content_json, ensure_ascii=False)})
            messages.append({"role": "user", "content": question})

            if self._ai_provider.getSelectedItem() == "OpenAI":
                self.generate_openai_chat_response(messages)
            else:
                self.generate_claude_chat_response(messages)
        else:
            JOptionPane.showMessageDialog(None, "No requests selected to send.")                


    def obfuscate_url(self, url_str):
        try:
            url = URL(url_str)
            original_host = url.getHost()
            random_host = self.generate_random_hostname(original_host)
            obfuscated_url = URL(url.getProtocol(), random_host, url.getPort(), url.getFile()).toString()
            return obfuscated_url
        except Exception as e:
            return url_str

    def obfuscate_hosts_in_request(self, request_content):
        request_lines = request_content.split('\n')
        for i in range(len(request_lines)):
            if request_lines[i].lower().startswith('host:'):
                original_host = request_lines[i].split(':', 1)[1].strip()
                request_lines[i] = 'Host: {}'.format(self.generate_random_hostname(original_host))
        obfuscated_request = '\n'.join(request_lines)
        obfuscated_request = self.replace_urls_in_text(obfuscated_request)
        return obfuscated_request

    def obfuscate_hosts_in_response(self, response_content):
        # Replace URLs in the response body
        obfuscated_response = self.replace_urls_in_text(response_content)
        # Replace any remaining hostnames
        obfuscated_response = self.replace_hostnames_in_text(obfuscated_response)
        return obfuscated_response
    
    def replace_urls_in_text(self, text):
        url_pattern = re.compile(r'(https?://)([^\s/:]+)(:[0-9]+)?(/[^\s]*)?')
        return url_pattern.sub(lambda m: m.group(1) + self.generate_random_hostname(m.group(2)) + (m.group(3) if m.group(3) else '') + (m.group(4) if m.group(4) else ''), text)
    
    def replace_hostnames_in_text(self, text):
        hostname_pattern = re.compile(r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b', re.IGNORECASE)
        return hostname_pattern.sub(lambda m: self.generate_random_hostname(m.group(0)), text)
    def generate_random_hostname(self, original_host):
        if original_host in self._obfuscation_map:
            return self._obfuscation_map[original_host]
        
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        random_host = ''.join([chars[self._random_generator.nextInt(len(chars))] for _ in range(10)]) + '.com'
        self._obfuscation_map[original_host] = random_host
        return random_host

    def generate_openai_chat_response(self, messages):
        api_key = self._api_key_field.getText()

        self._chat_area.setText("Loading...")

        try:
            url = URL("https://api.openai.com/v1/chat/completions")
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setRequestProperty("Authorization", "Bearer {}".format(api_key))
            connection.setDoOutput(True)

            data = {
                "model": self._model_selector.getSelectedItem(),
                "messages": messages
            }

            json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')

            # Imprimir la información de la petición
            print("DEBUG - Request URL: {}".format(url).encode('utf-8'))
            print("DEBUG - Request Method: POST".encode('utf-8'))
            print("DEBUG - Request Headers:".encode('utf-8'))
            for key, value in connection.getRequestProperties().items():
                print("  {}: {}".format(key, value).encode('utf-8'))
            print("DEBUG - Request Body:".encode('utf-8'))
            try:
                print(json_data.decode('utf-8').encode('utf-8'))
            except UnicodeEncodeError:
                print(json_data.decode('utf-8').encode('utf-8'))

            output_stream = connection.getOutputStream()
            output_stream.write(json_data)
            output_stream.close()

            # Imprimir el código de respuesta
            print("DEBUG - Response Code: {}".format(connection.getResponseCode()).encode('utf-8'))

            if connection.getResponseCode() == 200:
                input_stream = connection.getInputStream()
                buffered_reader = BufferedReader(InputStreamReader(input_stream, 'utf-8'))

                response = StringBuilder()

                line = buffered_reader.readLine()
                while line is not None:
                    response.append(line)
                    line = buffered_reader.readLine()

                buffered_reader.close()

                # Imprimir la respuesta
                try:
                    print("DEBUG - Response Body:".encode('utf-8'))
                    print(response.toString().encode('utf-8'))
                except UnicodeEncodeError:
                    print("DEBUG - Response Body (encoded): {}".format(response.toString().encode('utf-8')).encode('utf-8'))

                response_json = json.loads(response.toString())
                chat_response = response_json['choices'][0]['message']['content']
                self._chat_area.setText(chat_response)
            else:
                error_message = "Error: HTTP {}".format(connection.getResponseCode())
                self._chat_area.setText(error_message)
                print("DEBUG - " + error_message.encode('utf-8'))

        except Exception as e:
            error_message = "Error: {}".format(str(e))
            self._chat_area.setText(error_message)
            try:
                print("DEBUG - " + error_message.encode('utf-8'))
            except UnicodeEncodeError:
                print("DEBUG - " + error_message.encode('utf-8'))
            print("DEBUG - Detailed error: {}".format(e).encode('utf-8'))


        except Exception as e:
            error_message = "Error: {}".format(str(e))
            self._chat_area.setText(error_message)
            try:
                print("DEBUG - " + error_message)
            except UnicodeEncodeError:
                print("DEBUG - " + error_message.encode('utf-8'))
            print("DEBUG - Detailed error: {}".format(e).encode('utf-8'))


    def generate_claude_chat_response(self, messages):
        # Logic to communicate with Claude's API
        self._chat_area.setText("Claude functionality is not implemented yet.")

    def post_request(self, url, headers, data):
        import ssl
        from urllib2 import Request, urlopen
        ssl._create_default_https_context = ssl._create_unverified_context

        request = Request(url, data.encode('utf-8'), headers)
        response = urlopen(request)
        return response.read().decode('utf-8')

    def clear_requests(self, event):
        self._table_model.setRowCount(0)
        self._request_responses = []
        self._request_viewer.setMessage(None, True)
        self._response_viewer.setMessage(None, False)

    def getTabCaption(self):
        return "BurpAI Chat"

    def getUiComponent(self):
        return self._main_panel