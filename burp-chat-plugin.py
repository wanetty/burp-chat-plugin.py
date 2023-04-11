from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JTable, ListSelectionModel, JLabel, JTextField, Box
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
from java.awt.event import ActionListener
from java.io import BufferedReader, InputStreamReader
from java.lang import StringBuilder
from java.net import URL, HttpURLConnection
from java.net import URLDecoder
import json, base64


class BurpExtender(IBurpExtender, ITab, IHttpListener, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp Chat Plugin")

        self.init_gui()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def init_gui(self):
        self._main_panel = JPanel(BorderLayout())
        self._send_button = JButton("Send to OpenAI Chat", actionPerformed=self.send_to_openai_chat)
        self._chat_area = JTextArea(10, 50)
        self._system_area = JTextArea(10, 50)

        column_names = ["#", "Method", "URL", "Request Content", "Response Content"]
        self._table_model = DefaultTableModel(column_names, 0)
        self._request_table = JTable(self._table_model)
        self._request_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        self._api_key_label = JLabel("API Key:")
        self._api_key_field = JTextField(30)

        api_key_box = Box.createHorizontalBox()
        api_key_box.add(self._api_key_label)
        api_key_box.add(self._api_key_field)
        api_key_box.add(self._send_button)

        self._main_panel.add(api_key_box, BorderLayout.NORTH)
        self._main_panel.add(JScrollPane(self._request_table), BorderLayout.CENTER)
        self._main_panel.add(JScrollPane(self._chat_area), BorderLayout.SOUTH)
        self._main_panel.add(JScrollPane(self._system_area), BorderLayout.EAST)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            request = self._helpers.analyzeRequest(messageInfo)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            url = request.getUrl().toString()
            method = request.getMethod()
            request_content = messageInfo.getRequest().tostring()
            
            body_offset = response_info.getBodyOffset()
            response_content = self._helpers.bytesToString(messageInfo.getResponse()[body_offset:])
            
            print(response_content)
            row_data = [self._table_model.getRowCount() + 1, method, url, request_content, response_content]
            self._table_model.addRow(row_data)

    def send_to_openai_chat(self, event):
        selected_rows = self._request_table.getSelectedRows()
        print(selected_rows)
        if selected_rows:
            messages = [{"role": "system", "content": "Usted es un asistente pentester. Recibes un JSON desde diferentes URLs. El campo response viene codificado en base64, antes de analizar la pregunta tienes que decodificar este campo."}]
            question = self._system_area.getText()
            print ("Entro1")
            for row in selected_rows:
                
                method = self._table_model.getValueAt(row, 1)
                request_info = self._table_model.getValueAt(row, 2)
                #As of today, the answer is too long for chatGPT to interpret.
                #response_content = self._table_model.getValueAt(row, 4)
                #response_content_encoded = base64.b64encode(self._helpers.stringToBytes(response_content)).decode("utf-8")
                content_json = {"url": request_info, "method": method}
                messages.append({"role": "user", "content": json.dumps(content_json)})
            messages.append({"role": "user", "content": question})
            self.generate_chat_response(messages)

    def generate_chat_response(self, messages):
        api_key = self._api_key_field.getText()
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key
        }
        data = {
            "model": "gpt-3.5-turbo",
            "messages": messages
        }

        self._chat_area.setText("Cargando...")

        try:
            print("Sending JSON:", json.dumps(data))  # Debug message
            response = self.post_request("https://api.openai.com/v1/chat/completions", headers, json.dumps(data))
            response_json = json.loads(response)
            chat_response = response_json['choices'][0]['message']['content']
            self._chat_area.setText(chat_response)
        except Exception as e:
            print("Sending JSON:", json.dumps(data))  # Debug message
            self._chat_area.setText(str(e))

    def post_request(self, url, headers, data):
        url_obj = URL(url)
        connection = url_obj.openConnection()
        connection.setDoOutput(True)
        connection.setRequestMethod("POST")

        for header_key, header_value in headers.items():
            connection.setRequestProperty(header_key, header_value)

        connection.getOutputStream().write(data.encode("utf-8"))

        response_code = connection.getResponseCode()
        if response_code == 200:
            reader = BufferedReader(InputStreamReader(connection.getInputStream()))
            result = StringBuilder()
            line = reader.readLine()
            while line is not None:
                result.append(line)
                line = reader.readLine()
            reader.close()
            return result.toString()
        else:
            raise Exception("Error al realizar la solicitud: codigo de respuesta {}".format(response_code))

    def getTabCaption(self):
        return "BurpGPT Chat"

    def getUiComponent(self):
        return self._main_panel
