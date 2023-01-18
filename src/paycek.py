import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64encode

import requests


class Paycek:
	def __init__(self, api_key: str, api_secret: str):
		self.api_secret = api_secret
		self.api_key = api_key
		self.api_host = 'https://paycek.io'
		self.api_prefix = '/processing/api'
		self.encoding = 'utf-8'

	def _generate_mac_hash(self, nonce_str: str, endpoint: str, body_bytes: bytes, key=None, secret=None, http_method='POST', content_type='application/json'):
		key = self.api_key if key is None else key
		secret = self.api_secret if secret is None else secret

		mac = hashlib.sha3_512()
		mac.update(b'\0')
		mac.update(key.encode(self.encoding))
		mac.update(b'\0')
		mac.update(secret.encode(self.encoding))
		mac.update(b'\0')
		mac.update(nonce_str.encode(self.encoding))
		mac.update(b'\0')
		mac.update(http_method.encode(self.encoding))
		mac.update(b'\0')
		mac.update(endpoint.encode(self.encoding))
		mac.update(b'\0')
		mac.update(content_type.encode(self.encoding))
		mac.update(b'\0')
		mac.update(body_bytes)
		mac.update(b'\0')

		return mac.hexdigest()

	def _api_call(self, endpoint: str, body: dict):
		endpoint = f'{self.api_prefix}/{endpoint}'
		body_bytes = json.dumps(body).encode(self.encoding)

		nonce_str = str(int(time.time() * 1000))

		mac_hash = self._generate_mac_hash(
			nonce_str=nonce_str,
			endpoint=endpoint,
			body_bytes=body_bytes
		)

		headers = {
			'Content-Type': 'application/json',
			'ApiKeyAuth-Key': self.api_key,
			'ApiKeyAuth-Nonce': nonce_str,
			'ApiKeyAuth-MAC': mac_hash
		}

		r = requests.request(
			method='POST',
			url=f'{self.api_host}{endpoint}',
			data=body_bytes,
			headers=headers
		)

		r.encoding = self.encoding

		return r.json()

	def check_headers(self, headers, endpoint, body_bytes, key: str, secret: str, http_method='GET', content_type=''):
		generated_mac = self._generate_mac_hash(headers['Apikeyauth-Nonce'], endpoint, body_bytes, key, secret, http_method, content_type)

		return hmac.compare_digest(headers['Apikeyauth-Mac'], generated_mac)

	def generate_payment_url(self, profile_id, secret_key, payment_id, total_amount, items=None, email='', success_url='', fail_url='', back_url='', success_url_callback='', fail_url_callback='', status_url_callback='', description='', language=''):
		"""
		:param profile_id: string, unique profile id (id that you are using on your website to uniquely describe payment profile)
		:param secret_key: string, profile secret key
		:param payment_id: string, unique payment id (id that you are using on your website to uniquely describe the purchase)
		:param total_amount: string, total price (example "100.00")
		:param items: array of dicts (this is used to display purchased items list to customer)
				example: [{'name': 'smartphone', 'units': '1', 'amount': '999.00'}, {'name': 'cable', 'units': '1', 'amount': '29.00'}]
		:param email: string, email of your customer
		:param success_url: string, URL of a web page to go to after a successful payment
		:param fail_url: string, URL of a web page to go to after a failed payment
		:param back_url: string, URL for client to go to if he wants to get back to your tool
		:param success_url_callback: string, URL of an API that paycek.io will call after successful payment
		:param fail_url_callback: string, URL of an API that paycek.io will call after failed payment
		:param status_url_callback: string, URL of an API that paycek.io will call after each payment status change (advanced)
				This callback will be called with an optional argument ?status=<status>&id=<payment_id>
					<status> options are listed bellow:
						created - payment has been created
						waiting_transaction - waiting for the amount to appear on blockchain
						waiting_confirmations - waiting for the right amount of confirmations
						underpaid - an insufficient amount detected on blockchain
						successful - right amount detected and confirmed on blockchain
						expired - time for this payment has run out
						canceled - the payment has been manually canceled by paycek operations
					<payment_id> is the payment_id you provided when you generated the URL
		:param description: string, payment description (max length 100 characters)
		:param language: string, language in which the payment will be shown to the customer ('en', 'hr')
		:return: string, URL for starting a payment process on https://paycek.io
		"""
		if items is None:
			items = []

		formatted_items = []
		for item in items:
			new_item = {
				'n': item['name'],
				'u': item['units'],
				'a': item['amount'],
			}
			formatted_items.append(new_item)

		data = {
			'p': total_amount,
			'id': payment_id,
			'e': email,
			's': success_url,
			'f': fail_url,
			'b': back_url,
			'sc': success_url_callback,
			'fc': fail_url_callback,
			'stc': status_url_callback,
			'd': description,
			'i': formatted_items,
			'l': language,
		}

		data_json = json.dumps(data, separators=(',', ':'))
		data_b64 = urlsafe_b64encode(data_json.encode('utf-8')).rstrip(b'=')

		sha256 = hashlib.sha256()
		sha256.update(data_b64)
		sha256.update(b'\x00')
		sha256.update(profile_id.encode(self.encoding))
		sha256.update(b'\x00')
		sha256.update(secret_key.encode(self.encoding))
		data_hash = urlsafe_b64encode(sha256.digest()).rstrip(b'=').decode(self.encoding)

		payment_url = f'{self.api_host}/processing/checkout/payment_create?d={data_b64.decode(self.encoding)}&c={profile_id}&h={data_hash}'

		return payment_url

	def get_payment(self, payment_code: str):
		body = {
			"payment_code": payment_code
		}

		return self._api_call('payment/get', body)

	def open_payment(self, profile_code: str, dst_amount: str, **optional_fields):
		"""
		:param optional_fields: Optional fields:
			payment_id: “string
			location_id: string
			items: array
			email: string
			success_url: string
			fail_url: string
			back_url: string
			success_url_callback: string
			fail_url_callback: string
			status_url_callback: string
			description: string
			language: string
			generate_pdf: bool
			client_fields: dict
		"""
		body = {
			"profile_code": profile_code,
			"dst_amount": dst_amount,
			**optional_fields
		}

		return self._api_call('payment/open', body)

	def update_payment(self, payment_code: str, src_currency: str):
		body = {
			"payment_code": payment_code,
			"src_currency": src_currency
		}

		return self._api_call('payment/update', body)

	def cancel_payment(self, payment_code: str):
		body = {
			"payment_code": payment_code
		}

		return self._api_call('payment/cancel', body)

	def get_profile_info(self, profile_code: str):
		body = {
			"profile_code": profile_code
		}

		return self._api_call('profile_info/get', body)

	def profile_withdraw(self, profile_code: str, method: str, amount: str, details: dict, **optional_fields):
		"""
		:param details: Withdraw details object with fields:
			iban: str (required)
			purpose: str
			model: str
			pnb: str
		:param optional_fields: Optional fields:
			id: str
		"""
		body = {
			"profile_code": profile_code,
			"method": method,
			"amount": amount,
			"details": details,
			**optional_fields
		}

		return self._api_call('profile/withdraw', body)

	def create_account(self, email: str, name: str, street: str, city: str, country: str, profile_currency: str, profile_automatic_withdraw_method: str, profile_automatic_withdraw_details: dict, **optional_fields):
		"""
		:param profile_automatic_withdraw_details: Automatic withdraw details object with fields:
			iban: str (required)
			purpose: str
			model: str
			pnb: str
		:param optional_fields: Optional fields:
			type: str
			oib: str
			vat: str
			profile_name: str
			profile_email: str
			profile_type: str
		"""
		body = {
			"email": email,
			"name": name,
			"street": street,
			"city": city,
			"country": country,
			"profile_currency": profile_currency,
			"profile_automatic_withdraw_method": profile_automatic_withdraw_method,
			"profile_automatic_withdraw_details": profile_automatic_withdraw_details,
			**optional_fields
		}

		return self._api_call('account/create', body)

	def create_account_with_password(self, email: str, password: str, name: str, street: str, city: str, country: str, profile_currency: str, profile_automatic_withdraw_method: str, profile_automatic_withdraw_details: dict, **optional_fields):
		"""
		:param profile_automatic_withdraw_details: Automatic withdraw details object with fields:
			iban: str (required)
			purpose: str
			model: str
			pnb: str
		:param optional_fields: Optional fields:
			type: str
			oib: str
			vat: str
			profile_name: str
			profile_email: str
		"""
		body = {
			"email": email,
			"password": password,
			"name": name,
			"street": street,
			"city": city,
			"country": country,
			"profile_currency": profile_currency,
			"profile_automatic_withdraw_method": profile_automatic_withdraw_method,
			"profile_automatic_withdraw_details": profile_automatic_withdraw_details,
			**optional_fields
		}

		return self._api_call('account/create_with_password', body)

	def get_reports(self, profile_code: str, datetime_from: str, datetime_to: str, **optional_fields):
		"""
		:param profile_automatic_withdraw_details: Automatic withdraw details object with fields:
			iban: str (required)
			purpose: str
			model: str
			pnb: str
		:param optional_fields: Optional fields:
			location_id: str
		"""
		body = {
			"profile_code": profile_code,
			"datetime_from": datetime_from,
			"datetime_to": datetime_to,
			**optional_fields
		}

		return self._api_call('reports/get', body)
