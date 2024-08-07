from django.db import models
from django.utils import timezone


class TransactionsLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    client_ip = models.CharField(max_length=30)
    data = models.TextField(null=True, blank=True)
    status_code = models.CharField(null=True, blank=True, max_length=10)
    response_status = models.CharField(null=True, blank=True, max_length=10)
    message = models.TextField(null=True, blank=True)

    class Meta:
        managed = True
        db_table = 'epayment_transactions_log'


class InquiryLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    client_ip = models.CharField(max_length=30)
    request_data = models.TextField(null=True, blank=True)
    response_data = models.TextField(null=True, blank=True)
    status_code = models.CharField(null=True, blank=True, max_length=10)
    response_status = models.CharField(null=True, blank=True, max_length=10)
    message = models.TextField(null=True, blank=True)

    class Meta:
        managed = True
        db_table = 'epayment_inquiry_log'

    def log(self, status_code, message, response_status, response_data = None):
        self.status_code = status_code
        self.message = message
        self.response_data = response_data
        self.response_status = response_status
        self.save()



