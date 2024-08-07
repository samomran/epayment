# from pylon.epayment.models.transactions_log import InquiryLogs
from .models.transactions_log import InquiryLog
class Validator:

    def __init__(self, request, log : InquiryLog):
        self.request = request
        self.log = log

    def validate(self):
        username = self.request.data.get('username', '')
        valid, error = self.validate_username(username)
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error 

        password = self.request.data.get('password', None) 
        valid, error = self.validate_password(password)      
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error
        
        amount = self.request.data.get('amount', None)
        valid, error = self.validate_amount(amount)
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error
        
        phone_number = self.request.data.get('phone_number', None)
        valid, error = self.validate_phone(phone_number)
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error
        
        transaction_number = self.request.data.get('trxId', None)
        valid, error = self.validate_transaction_number(transaction_number)
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error
        
        sender_gsm = self.validate_sender_gsm(sender_gsm)
        if not valid:
            self.log.log(
                status_code='0',
                message=error,
                response_status='400'
            )
            return False, error

        return True, None

    def validate_username(self, username):
        if username is None or len(str(username)) == 0:
            return False, "username is required"
        return True, None
    
    def validate_password(self, password):
        if password is None or len(str(password)) == 0:
            return False, 'invalid credentials'
        
        return True, None
    
    def validate_amount(self, amount):
        if amount is None:
            return False, 'amount is required'
        
        try:
            amount = float(amount)
            if amount <= 0:
                return False, 'invalid amount value'
        except:
            return False, 'invalid amount value'
        
        return True, None
    
    def validate_phone(self, phone_number):
        if phone_number is None or len(str(phone_number)) == 0:
            return False, "phone number is required"
        
        return True, None
        
    def validate_transaction_number(self, transaction_number):
        if transaction_number is None:
            return False, "transaction number is required"
        elif len(str(transaction_number)) == 0 or len(str(transaction_number)) > 100:
            return False, "invalid transaction number"
        
        return True, None

    def validate_sender_gsm(self, sender_gsm):
        return True, None