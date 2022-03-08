#!/usr/bin/env python3
import cbor2
import cose
import base64
import json

from cose import EC2, CoseAlgorithms, CoseEllipticCurves
from Crypto.Util.number import long_to_bytes
from OpenSSL import crypto

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from importlib import resources
import io


def encrypt(attestation_doc, plaintext):
    # Decode CBOR attestation document
    data = cbor2.loads(attestation_doc)

    # Load and decode document payload
    doc = data[2]
    doc_obj = cbor2.loads(doc)

    # Get the public key from attestation document
    public_key_byte = doc_obj['public_key']
    public_key = RSA.import_key(public_key_byte)

    # Encrypt the plaintext with the public key and encode the cipher text in base64
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(str.encode(plaintext))

    return base64.b64encode(ciphertext).decode()


def get_credentials(attestation_doc_b64):

    attestation_doc = base64.b64decode(attestation_doc_b64)
    att_doc_status = verify_attestation_doc(attestation_doc)
    if att_doc_status == False:
        return False

    account_id = "0000"
    mercury_token = "1234"
    encrypted_id = encrypt(attestation_doc, account_id)
    encrypted_token = encrypt(attestation_doc, mercury_token)

    credential_bundle = {
        "account_id": account_id,
        "mercury_token": mercury_token
    }

    credential_bundle_str = json.dumps(credential_bundle)

    encrypted_bundle = encrypt(attestation_doc, credential_bundle_str)

    return encrypted_bundle;


def verify_zip(uploadedZip):
    return True


def verify_attestation_doc(attestation_doc, expected_pcrs):
    # Decode CBOR attestation document
    data = cbor2.loads(attestation_doc)
    # Load and decode document payload
    doc = data[2]
    doc_obj = cbor2.loads(doc)

    pcr_status = verify_pcrs(doc_obj, expected_pcrs)
    if not pcr_status: return False

    signature_status = validate_signature(data, doc, doc_obj)
    if not signature_status: return False


    pki_status = validate_pki(doc_obj)
    if not pki_status: return False

    return True;

def verify_pcrs(doc_obj, expected_pcrs ):
    # Get PCRs from attestation document
    document_pcrs_arr = doc_obj['pcrs']

    for pcr_key in expected_pcrs.keys():
        index = int(pcr_key)

        # Attestation document doesn't have specified PCR, raise exception
        if index not in document_pcrs_arr or document_pcrs_arr[index] is None:
            print("Wrong PCR%s" % index)
            return False

        pcr = expected_pcrs[pcr_key]
        doc_pcr = document_pcrs_arr[index].hex()
        
        # Check if PCR match
        if pcr != doc_pcr:
            print("Wrong pcr {}".format(index))
            return False

    return True


def validate_signature(data, doc, doc_obj):
    # Get signing certificate from attestation document
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, doc_obj['certificate'])

    # Get the key parameters from the cert public key
    cert_public_numbers = cert.get_pubkey().to_cryptography_key().public_numbers()
    x = cert_public_numbers.x
    y = cert_public_numbers.y
    curve = cert_public_numbers.curve

    x = long_to_bytes(x)
    y = long_to_bytes(y)

    # Create the EC2 key from public key parameters
    key = EC2(alg = CoseAlgorithms.ES384, x = x, y = y, crv = CoseEllipticCurves.P_384)

    # Get the protected header from attestation document
    phdr = cbor2.loads(data[0])

    # Construct the Sign1 message
    msg = cose.Sign1Message(phdr = phdr, uhdr = data[1], payload = doc)
    msg.signature = data[3]

    # Verify the signature using the EC2 key
    if not msg.verify_signature(key):
        print("Wrong signature")
        return False

    return True


def validate_pki(doc_obj):
    bin_file = None
    with resources.open_binary('wsock_secrets_provider', 'root.pem') as fp:
        bin_file = fp.read()

    root_cert_pem = bin_file.decode('utf-8')

    # Get signing certificate from attestation document
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, doc_obj['certificate'])

    if root_cert_pem is not None:
        # Create an X509Store object for the CA bundles
        store = crypto.X509Store()

        # Create the CA cert object from PEM string, and store into X509Store
        _cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_pem)
        store.add_cert(_cert)

        # Get the CA bundle from attestation document and store into X509Store
        # Except the first certificate, which is the root certificate
        for _cert_binary in doc_obj['cabundle'][1:]:
            _cert = crypto.load_certificate(crypto.FILETYPE_ASN1, _cert_binary)
            store.add_cert(_cert)

        # Get the X509Store context
        store_ctx = crypto.X509StoreContext(store, cert)

        # Validate the certificate
        # If the cert is invalid, it will raise exception
        try:
            store_ctx.verify_certificate()
        except Exception as e:
            print("PKI")
            print(e)

    return True
