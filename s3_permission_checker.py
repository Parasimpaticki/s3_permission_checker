import re
import minio
import tldextract
from urlparse import urlparse
from burp import IBurpExtender, IExtensionStateListener, ITab, IHttpListener
from javax.swing import JPanel, JTextField, JButton, JLabel, BoxLayout, JPasswordField
from javax.swing import JTable
from javax.swing.table import DefaultTableModel

EXT_NAME = 'S3 Permission Checker'
ENABLED = '<html><h2><font color="green">Enabled</font></h2></html>'
DISABLED = '<html><h2><font color="red">Disabled</font></h2></html>'

class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IHttpListener):
    def __init__(self):
        self.aws_access_key_id = ''
        self.aws_secret_accesskey = ''

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.helpers
        self.isEnabled = False

        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.setExtensionName(EXT_NAME)
        callbacks.addSuiteTab(self)

    # Called on "save" button click to save the settings
    def saveKeys(self, event):
        aws_access_key_id = self.access_key.text
        aws_secret_access_key = self.secret_key.text
        self.callbacks.saveExtensionSetting(
            "aws_access_key_id", aws_access_key_id)
        self.callbacks.saveExtensionSetting(
            "aws_secret_access_key", aws_secret_access_key)
        return

    def switchStatus(self, event):
        if self.isEnabled:
            self.status_indicator.text = DISABLED
            self.isEnabled = False
            self.enable_button.setEnabled(True)
            self.secret_key.setEnabled(True)
            self.access_key.setEnabled(True)
            self.disable_button.setEnabled(False)
        else:
            self.status_indicator.text = ENABLED
            self.isEnabled = True
            self.enable_button.setEnabled(False)
            self.secret_key.setEnabled(False)
            self.access_key.setEnabled(False)
            self.disable_button.setEnabled(True)

    def is_new_bucket(self, bucket_name):
        num_rows = self.table_model.getRowCount()
        for row in range(num_rows):
            value = self.table_model.getValueAt(row, 0)
            if value == bucket_name:
                return False
        return True

    def check_s3_permissions(self, bucket_name):
        if not self.is_new_bucket(bucket_name):
            return

        access_key = self.access_key.text
        secret_key = self.secret_key.text

        # Create a client for the S3 service
        client = minio.Minio(
            endpoint='s3.amazonaws.com',
            access_key=access_key,
            secret_key=secret_key,
            secure=True
        )
        # Check if the bucket exists
        try:
            found = client.bucket_exists(bucket_name)
            if not found:
                print("[S3 Takeover] Bucket {} doesn't exist!".format(
                    bucket_name))
                self.table_model.addRow([bucket_name, "No", "/", "/"])
                self.table.updateUI()
                return
        except:
            pass
        # Check read access
        read = False
        try:
            objects = client.list_objects(bucket_name)
            for obj in objects:
                print("[{}] {}".format(bucket_name, obj))
            read = True
        except:
            pass
        # Check write access
        write = False
        try:
            client.put_object(bucket_name, 'test.txt', 'test data')
            write = True
            client.remove_object(bucket_name, 'test.txt')
        except:
            pass
        self.table_model.addRow([bucket_name, "Yes", str(read), str(write)])
        self.table.updateUI()

    def processHttpMessage(self, tool_name, message_is_request, message_info):
        if not self.isEnabled:
            return
        if message_is_request:
            request_info = self.helpers.analyzeRequest(message_info)
            request_headers = request_info.getHeaders()
            content = message_info.getRequest()[request_info.getBodyOffset():]
        else:
            response_info = self.helpers.analyzeResponse(
                message_info.getResponse())
            response_headers = response_info.getHeaders()
            content = message_info.getResponse(
            )[response_info.getBodyOffset():]

        # Get all S3 bucket names in the request or response
        s3_buckets = set(re.findall(
            r"[a-zA-Z0-9.-]*\.?s3[\.-](?:[a-zA-Z0-9.-]*\.)?amazonaws\.com(?:/[a-zA-Z0-9.-]*)?", content))

        for bucket_name in s3_buckets:
            extracted = tldextract.extract(bucket_name)
            if extracted.subdomain.startswith('s3.'):
                bucket_name = urlparse(bucket_name).path[1:]
            else:
                bucket = extracted.subdomain.split('.s3.')
                if len(bucket) == 1:
                    bucket = extracted.subdomain.split('.s3')
                bucket_name = bucket[0]
            self.check_s3_permissions(bucket_name)

    # Tab name
    def getTabCaption(self):
        return EXT_NAME

    # Layout the UI
    def getUiComponent(self):
        aws_access_key_id = self.callbacks.loadExtensionSetting(
            "aws_access_key_id")
        aws_secret_accesskey = self.callbacks.loadExtensionSetting(
            "aws_secret_access_key")
        if aws_access_key_id:
            self.aws_access_key_id = aws_access_key_id
        if aws_secret_accesskey:
            self.aws_secret_accesskey = aws_secret_accesskey

        self.panel = JPanel()

        self.main = JPanel()
        self.main.setLayout(BoxLayout(self.main, BoxLayout.Y_AXIS))

        self.access_key_panel = JPanel()
        self.main.add(self.access_key_panel)
        self.access_key_panel.setLayout(
            BoxLayout(self.access_key_panel, BoxLayout.X_AXIS))
        self.access_key_panel.add(JLabel('Access Key: '))
        self.access_key = JTextField(self.aws_access_key_id, 25)
        self.access_key_panel.add(self.access_key)

        self.secret_key_panel = JPanel()
        self.main.add(self.secret_key_panel)
        self.secret_key_panel.setLayout(
            BoxLayout(self.secret_key_panel, BoxLayout.X_AXIS))
        self.secret_key_panel.add(JLabel('Secret Key: '))
        self.secret_key = JPasswordField(self.aws_secret_accesskey, 25)
        self.secret_key_panel.add(self.secret_key)

        self.buttons_panel = JPanel()
        self.main.add(self.buttons_panel)
        self.buttons_panel.setLayout(
            BoxLayout(self.buttons_panel, BoxLayout.X_AXIS))
        self.save_button = JButton('Save Keys', actionPerformed=self.saveKeys)
        self.buttons_panel.add(self.save_button)
        self.enable_button = JButton(
            'Enable', actionPerformed=self.switchStatus)
        self.buttons_panel.add(self.enable_button)
        self.disable_button = JButton(
            'Disable', actionPerformed=self.switchStatus)
        self.buttons_panel.add(self.disable_button)
        self.disable_button.setEnabled(False)

        self.status = JPanel()
        self.main.add(self.status)
        self.status.setLayout(BoxLayout(self.status, BoxLayout.X_AXIS))
        self.status_indicator = JLabel(DISABLED, JLabel.CENTER)
        self.status_indicator.putClientProperty("html.disable", None)
        self.status.add(self.status_indicator)

        self.table = JTable(1, 4)
        self.table_model = DefaultTableModel(
            [["Bucket Name", "Exists", "Read Access", "Write Access"]],
            ["Bucket Name", "Exists", "Read Access", "Write Access"]
        )
        self.table.setModel(self.table_model)
        self.table.getColumnModel().getColumn(0).setPreferredWidth(350)
        self.main.add(self.table)

        self.panel.add(self.main)
        return self.panel
