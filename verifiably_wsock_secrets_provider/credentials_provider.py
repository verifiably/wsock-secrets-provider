import websocket
import json
import rel
import boto3
import base64
from verifiably_checker import attestation
import traceback

class SecretsProvider():
    def __init__(self, credentials, expected_pcrs):
        self.credentials = credentials
        self.expected_pcrs = expected_pcrs

    def update_pcrs(self, expected_pcrs):
        self.expected_pcrs = expected_pcrs

    def update_credentials(self,  credentials):
        self.credentials = credentials

    def start(self):
        wsapp = websocket.WebSocketApp("wss://wsock.us-east-2.verifiably.com", on_message=self.on_message)
        wsapp.run_forever(dispatcher=rel)
        rel.signal(2, rel.abort)
        wsapp.send("hello")
        rel.dispatch()


    def encrypt_credentials(self, attestation_doc):

        credential_bundle = self.credentials

        credential_bundle_str = json.dumps(credential_bundle)
        encrypted_bundle = attestation.encrypt(attestation_doc, credential_bundle_str)

        return encrypted_bundle;


    def send_credentials(self, v_function_connection_id, att_doc_b64, aws_credentials):
        client = boto3.client(
            'apigatewaymanagementapi',
            endpoint_url="https://wsock.us-east-2.verifiably.com",
            region_name = aws_credentials["Region"],
            aws_access_key_id = aws_credentials["AccessKeyId"],
            aws_secret_access_key = aws_credentials["SecretAccessKey"],
            aws_session_token = aws_credentials["SessionToken"])


        attestation_doc = base64.b64decode(att_doc_b64)
        att_doc_status = False
        try:
            att_doc_status = attestation.verify_attestation_doc(
                attestation_doc, self.expected_pcrs)
        except Exception:
            print("Invalid attesttion document")
            # print(e)
            print(traceback.format_exc())
            return

        if att_doc_status == False:
            print("Invalid attestation document")
            return


        encrypted_credentials = self.encrypt_credentials(attestation_doc)

        try:
            print("Sending credentials back")
            client.post_to_connection(
                Data=encrypted_credentials,
                ConnectionId=v_function_connection_id
            )
        except Exception as e:
            print("Caught exception:")
            print(e)

    def on_message(self, wsapp, message):
        message_json = json.loads(message)
        if 'connectionId' in message_json:
            print("Your connectionId: %s" %message_json['connectionId'])
        elif 'vFunctionConnectionId' in message_json:
            print("Received credentials request: %s" %message)
            try:
                self.send_credentials(message_json['vFunctionConnectionId'],
                                      message_json['att_doc'],
                                      message_json['aws_credentials'])
            except Exception as e:
                print(e)
