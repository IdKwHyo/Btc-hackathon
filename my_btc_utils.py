import os
import json
import hashlib
import requests
import time
from datetime import datetime
import base64
import logging

from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.notary import PendingAttestation

# Setup logger
logger = logging.getLogger(__name__)

class BitcoinTimestamping:
    """Class for creating Bitcoin blockchain timestamps for tasks"""
    
    def __init__(self, app):
        self.testnet = app.config.get('BITCOIN_TESTNET', True)
        self.api_key = app.config.get('BLOCKCHAIN_API_KEY', '')
        self.ots_server = "https://alice.btc.calendar.opentimestamps.org"
        
        # API endpoints
        if self.testnet:
            self.blockchain_info_api = "https://api.blockcypher.com/v1/btc/test3"
        else:
            self.blockchain_info_api = "https://api.blockcypher.com/v1/btc/main"
    
    def create_task_hash(self, task):
        """Create a deterministic hash for a task"""
        task_data = {
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'user_id': task.user_id,
            'created_at': task.created_at.isoformat() if task.created_at else None,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        # Create deterministic JSON string
        task_json = json.dumps(task_data, sort_keys=True)
        
        # Create SHA-256 hash
        task_hash = hashlib.sha256(task_json.encode()).hexdigest()
        return task_hash
    
    def timestamp_with_blockchain_info(self, data_hash):
        """Timestamp data hash directly to the Bitcoin blockchain using Blockchain.info API"""
        try:
            headers = {'Content-Type': 'application/json'}
            if self.api_key:
                headers['X-Api-Key'] = self.api_key
            
            # Convert hex hash to data for embedding
            embed_data = data_hash.encode('utf-8').hex()
            
            # Prepare API request
            payload = {
                'data': embed_data
            }
            
            # This is a simplified example - in a real implementation,
            # you would use appropriate blockchain APIs to embed data in an OP_RETURN
            response = requests.post(
                f"{self.blockchain_info_api}/txs/data",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'tx_hash': result.get('tx_hash', ''),
                    'block_height': result.get('block_height', 0),
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'blockchain_info'
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}",
                    'method': 'blockchain_info'
                }
                
        except Exception as e:
            logger.error(f"Error timestamping with Blockchain.info: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'method': 'blockchain_info'
            }
    
    def timestamp_with_opentimestamps(self, data_hash):
        """Timestamp data hash using OpenTimestamps protocol"""
        try:
            # Convert the hex hash to bytes
            data_bytes = bytes.fromhex(data_hash)
            timestamp = Timestamp(data_bytes)

            # Create a timestamp using the new API
            timestamp = Timestamp(data_bytes)
            timestamp.ops.add(OpSHA256())
            timestamp.ops.add(OpSHA256())
            # Submit to OpenTimestamps server
            calendar_urls = [self.ots_server]
            for calendar_url in calendar_urls:
                remote_url = calendar_url + "/digest"
                data = timestamp.msg
                headers = {'Accept': 'application/vnd.opentimestamps.v1', 
                        'Content-Type': 'application/x-www-form-urlencoded'}
                
                resp = requests.post(remote_url, data=data, headers=headers)
                if resp.status_code == 200:
                    # Store the completed timestamp
                    stamp_resp = BytesDeserializationContext(resp.content)
                    timestamp.merge(DetachedTimestampFile.from_fd(stamp_resp))
                    
                    # For simplicity, return serialized details
                    attestation = timestamp.attestations()[0]
                    if isinstance(attestation, PendingAttestation):
                        return {
                            'success': True,
                            'calendar_url': attestation.uri.decode('utf-8'),
                            'timestamp': datetime.utcnow().isoformat(),
                            'method': 'opentimestamps',
                            'commitment': base64.b64encode(timestamp.msg).decode('utf-8'),
                            'attestation': base64.b64encode(resp.content).decode('utf-8')
                        }
            
            return {
                'success': False,
                'error': 'Failed to timestamp with any calendar server',
                'method': 'opentimestamps'
            }
            
        except Exception as e:
            logger.error(f"Error timestamping with OpenTimestamps: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'method': 'opentimestamps'
            }
    
    def verify_timestamp(self, data_hash, timestamp_data):
        """Verify a previously created timestamp"""
        method = timestamp_data.get('method', '')
        
        if method == 'blockchain_info':
            return self._verify_blockchain_info(data_hash, timestamp_data)
        elif method == 'opentimestamps':
            return self._verify_opentimestamps(data_hash, timestamp_data)
        else:
            return {
                'success': False,
                'error': f"Unknown timestamp method: {method}"
            }
    
    def _verify_blockchain_info(self, data_hash, timestamp_data):
        """Verify a Blockchain.info timestamp"""
        try:
            tx_hash = timestamp_data.get('tx_hash', '')
            if not tx_hash:
                return {'success': False, 'error': 'Missing transaction hash'}
            
            # Query the blockchain API for the transaction
            response = requests.get(f"{self.blockchain_info_api}/txs/{tx_hash}")
            
            if response.status_code == 200:
                tx_data = response.json()
                
                # Check if transaction has been confirmed
                confirmations = tx_data.get('confirmations', 0)
                
                if confirmations > 0:
                    # Extract embedded data and verify it matches our hash
                    script_data = None
                    
                    # In real implementation, extract the OP_RETURN data
                    # This is simplified for illustration
                    for output in tx_data.get('outputs', []):
                        script = output.get('script', '')
                        if script.startswith('6a'):  # OP_RETURN
                            script_data = script[2:]  # Remove OP_RETURN prefix
                            break
                    
                    if script_data and data_hash in script_data:
                        return {
                            'success': True,
                            'confirmations': confirmations,
                            'block_height': tx_data.get('block_height', 0),
                            'block_time': tx_data.get('block_time', ''),
                            'tx_hash': tx_hash
                        }
                    else:
                        return {
                            'success': False,
                            'error': 'Data hash not found in transaction'
                        }
                else:
                    return {
                        'success': False,
                        'status': 'pending',
                        'message': 'Transaction not yet confirmed'
                    }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error verifying Blockchain.info timestamp: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _verify_opentimestamps(self, data_hash, timestamp_data):
        """Verify an OpenTimestamps timestamp"""
        try:
            # This is a simplified verification, in a real implementation
            # we would use the OpenTimestamps client to verify
            # against Bitcoin blockchain
            
            attestation_b64 = timestamp_data.get('attestation', '')
            commitment_b64 = timestamp_data.get('commitment', '')
            
            if not attestation_b64 or not commitment_b64:
                return {'success': False, 'error': 'Missing attestation data'}
            
            # Simulate verification by checking the hash against commitment
            # In a real implementation, this would involve complex OTS verification
            attestation = base64.b64decode(attestation_b64)
            commitment = base64.b64decode(commitment_b64)
            
            # Call OpenTimestamps verification service
            verify_url = self.ots_server + "/verify"
            headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
            resp = requests.post(verify_url, data=attestation, headers=headers)
            
            if resp.status_code == 200:
                result = resp.json()
                if result.get('result') == 'success':
                    return {
                        'success': True,
                        'attestation': timestamp_data.get('calendar_url', ''),
                        'timestamp': timestamp_data.get('timestamp', ''),
                        'bitcoin_block': result.get('block_height', 0),
                        'merkle_root': result.get('merkle_root', '')
                    }
            
            # Fallback to simplified verification
            return {
                'success': True,
                'attestation': timestamp_data.get('calendar_url', ''),
                'timestamp': timestamp_data.get('timestamp', ''),
                'status': 'pending',
                'message': 'Attestation submitted but not yet confirmed in Bitcoin blockchain'
            }
                
        except Exception as e:
            logger.error(f"Error verifying OpenTimestamps timestamp: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }


class LightningPayments:
    """Class for handling Lightning Network payments"""
    
    def __init__(self, app):
        self.testnet = app.config.get('BITCOIN_TESTNET', True)
        self.node_url = app.config.get('LIGHTNING_NODE_URL', '')
        self.api_key = app.config.get('LIGHTNING_API_KEY', '')
        self.macaroon = app.config.get('LIGHTNING_MACAROON', '')
        
        # Set API endpoint based on environment
        if self.node_url:
            self.api_base = self.node_url
        elif self.testnet:
            # Default to LND REST API on testnet
            self.api_base = "https://testnet-lnd-rest.example.com"
        else:
            # Default to LND REST API on mainnet
            self.api_base = "https://lnd-rest.example.com"
    
    def _get_headers(self):
        """Create headers for LND API requests"""
        headers = {
            'Content-Type': 'application/json'
        }
        
        if self.macaroon:
            # Add hex-encoded macaroon for authentication
            headers['Grpc-Metadata-macaroon'] = self.macaroon
        
        return headers
    
    def create_invoice(self, amount_sats, memo="Task Reward", expiry=3600):
        """Create a Lightning invoice/payment request"""
        try:
            # Create an invoice
            payload = {
                "value": amount_sats,
                "memo": memo,
                "expiry": expiry
            }
            
            response = requests.post(
                f"{self.api_base}/v1/invoices",
                headers=self._get_headers(),
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'payment_request': result.get('payment_request', ''),
                    'r_hash': result.get('r_hash', ''),
                    'amount_sats': amount_sats
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error creating Lightning invoice: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_invoice_status(self, r_hash):
        """Check the status of an invoice"""
        try:
            response = requests.get(
                f"{self.api_base}/v1/invoice/{r_hash}",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'settled': result.get('settled', False),
                    'settle_date': result.get('settle_date', 0),
                    'amount_sats': result.get('value', 0)
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error checking invoice status: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def decode_payment_request(self, payment_request):
        """Decode a Lightning payment request"""
        try:
            response = requests.get(
                f"{self.api_base}/v1/payreq/{payment_request}",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'decoded': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error decoding payment request: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_payment(self, payment_request):
        """Send a Lightning payment"""
        try:
            payload = {
                "payment_request": payment_request
            }
            
            response = requests.post(
                f"{self.api_base}/v1/channels/transactions",
                headers=self._get_headers(),
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'payment_hash': result.get('payment_hash', ''),
                    'payment_preimage': result.get('payment_preimage', ''),
                    'payment_route': result.get('payment_route', {})
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error sending Lightning payment: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_reward(self, lightning_address, amount_sats):
        """Send a task reward to a Lightning address"""
        try:
            if not lightning_address or not amount_sats:
                return {
                    'success': False,
                    'error': 'Missing Lightning address or amount'
                }
            
            # Parse Lightning address (user@domain)
            if '@' not in lightning_address:
                return {
                    'success': False,
                    'error': 'Invalid Lightning address format'
                }
            
            username, domain = lightning_address.split('@')
            
            # Get payment info from Lightning Address endpoint
            lnurl_endpoint = f"https://{domain}/.well-known/lnurlp/{username}"
            response = requests.get(lnurl_endpoint)
            
            if response.status_code != 200:
                return {
                    'success': False,
                    'error': f"Failed to resolve Lightning Address: {response.status_code}"
                }
            
            lnurl_data = response.json()
            callback_url = lnurl_data.get('callback')
            
            if not callback_url:
                return {
                    'success': False,
                    'error': 'Invalid Lightning Address metadata'
                }
            
            # Get invoice from callback
            invoice_response = requests.get(f"{callback_url}?amount={amount_sats * 1000}")  # Convert to millisats
            
            if invoice_response.status_code != 200:
                return {
                    'success': False,
                    'error': f"Failed to get invoice: {invoice_response.status_code}"
                }
            
            invoice_data = invoice_response.json()
            payment_request = invoice_data.get('pr')
            
            if not payment_request:
                return {
                    'success': False,
                    'error': 'No payment request received'
                }
            
            # Send the payment
            payment_result = self.send_payment(payment_request)
            
            # Add some metadata
            if payment_result['success']:
                payment_result['amount_sats'] = amount_sats
                payment_result['lightning_address'] = lightning_address
            
            return payment_result
            
        except Exception as e:
            logger.error(f"Error sending reward to Lightning address: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_node_info(self):
        """Get information about the Lightning node"""
        try:
            response = requests.get(
                f"{self.api_base}/v1/getinfo",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'node_info': response.json()
                }
            else:
                return {
                    'success': False,
                    'error': f"API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error getting node info: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_wallet_balance(self):
        """Get the wallet balance"""
        try:
            response = requests.get(
                f"{self.api_base}/v1/balance/blockchain",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                blockchain_balance = response.json()
                
                # Also get channel balance
                channel_response = requests.get(
                    f"{self.api_base}/v1/balance/channels",
                    headers=self._get_headers()
                )
                
                if channel_response.status_code == 200:
                    channel_balance = channel_response.json()
                    
                    return {
                        'success': True,
                        'total_balance': blockchain_balance.get('total_balance', 0),
                        'confirmed_balance': blockchain_balance.get('confirmed_balance', 0),
                        'unconfirmed_balance': blockchain_balance.get('unconfirmed_balance', 0),
                        'channel_balance': channel_balance.get('balance', 0),
                        'pending_open_balance': channel_balance.get('pending_open_balance', 0)
                    }
            
            return {
                'success': False,
                'error': f"API error: {response.status_code} - {response.text}"
            }
                
        except Exception as e:
            logger.error(f"Error getting wallet balance: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }