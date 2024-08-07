# ###################### REST & DJANGO #######################
from rest_framework.response import Response
from rest_framework import authentication, permissions
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import (detail_route, list_route,
                                       api_view, authentication_classes,
                                       permission_classes)
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated, DjangoModelPermissions, AllowAny
from rest_framework_jwt.settings import api_settings
# ######################### MODELS ##########################
from pylon.core.models import User, Customer, Pos, BaseService, Item, VisiblePermission
from pylon.billing.models import Invoice, Transaction, Bank
from pylon.orders.models import Order
# ######################### SERIALIZERS ##########################
from pylon.core.serializers import CustomerPortalSerializer, CustomerSearchSerializer, \
    PosSerializer, SubPosSerializer, PosWebSerializer, BaseServiceSerializer, \
    ItemSerializer, CustomerSerializer, ItemMobileSerializer,ContactInfoSerializer
from pylon.billing.serializers import (TransactionSerializer, InvoiceSerializer,
                                       BankSerializer, BankPaymentSerializer, PortalBankPaymentSerializer,
                                       TransactionSerializerPortal2)
from pylon.orders.serializers import OrderSerializer, PortalOrderSerializer
# ######################### SERVICES ############################
from pylon.core import core_app
from pylon.billing import billing_app
# ######################### MISC ############################
import traceback
from pprint import pprint
from pylon.config import SALES_CHANNELS
from pylon.sms.sms_app import sms_credit_transfer
from rest_framework_xml.renderers import XMLRenderer
from rest_framework.renderers import JSONRenderer
from django.db.models import Q
from pylon.helpers import token_expiry

from drf_renderer_xlsx.mixins import XLSXFileMixin
from rest_flex_fields import FlexFieldsModelViewSet
from rest_framework import pagination
from pylon.radiusapi.models import RadacctFull, Package, SpeedTest
from pylon.radiusapi.serializers import PortalCustomerSessionsSerializer, ExtraPackagesSerializer, SpeedTestSerializer
from datetime import datetime, timedelta
import datetime
from pylon.helpers import prev_month
from pylon.orders import orders_app
from pylon.ticketing.models import Category, Ticket, SubCategory, Inbox
from pylon.ticketing.serializers import TicketCategorySerializer, TicketSerializer, TicketSubCategorySerializer, \
    TicketInboxSerializerForCustomer
from pylon.sms import sms_app
from pylon.epayment.models.epayment_models import *
from pylon.notification.models import Notification
from pylon.notification.serializers import NotificationSerializer
from django.core.mail import send_mail
import requests
from pylon.config import CONFIG
from pylon.billing.models.bank import Bank
from django.contrib.auth.hashers import make_password
from rest_framework.status import HTTP_403_FORBIDDEN
from pylon.epayment.models.account import Account
from pylon.epayment.models.transactions_log import TransactionsLog
from django.db import transaction
from django.contrib.auth.hashers import check_password
from pylon.sms.sms_app import sms_credit_transfer
from pylon.epayment.models.transactions_log import InquiryLog
from dateutil.relativedelta import relativedelta
from django.utils import timezone

from validator import Validator
from .models.transactions_log import InquiryLog

MTN_BNK_ID = 9
SRY_BNK_ID = 11



class POSPagination(pagination.PageNumberPagination):
    page_size = 10

    def get_page_size(self, request):
        if request.GET.get('format', None) == 'xlsx':
            return 20000  # 20K for transactions
        else:
            return self.page_size

def get_client_ip(request):
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        ip = x_real_ip.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip



def get_body_response(data, message, status_code):
    body = {
        "data": data,
        "message": message,
        "status_code": status_code
    }
    return body

class EPayment(FlexFieldsModelViewSet):
    # authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = POSPagination

    # should be a decorator
    def allow_only(self, user, test):
        assert test in ["customer", "any"], "Only POS or Customer is allowed"
        if test == 'any':
            return True
        check = 3
        assert user.user_type_id == check, "Only " + test + " user is allowed"
        return True


    @transaction.atomic
    def create_transaction(self, trans_type_id, debit_id, credit_id,
                           status_id, channel, transaction_number, amount, phone_number, client_ip, bank_id, sender_gsm = None):
        t = Transaction.objects.create(
            trans_type_id=trans_type_id, debit_id=debit_id,
            credit_id=credit_id, status_id=status_id,
            channel=channel, bank_ref_no=transaction_number,
            bank_id=bank_id, amount=amount)
        Transactions.objects.create(customer_id=credit_id, operator_type=0,
                                    platform_type=0, amount=amount,
                                    tran_ref_id=t.id, mobile=phone_number, client_ip=client_ip, sender_gsm=sender_gsm)




    @list_route(methods=['POST'], url_path="credit_gsm", permission_classes=[], authentication_classes=[])
    def auth_gsm(self, request):
        client_ip = get_client_ip(request)
        log = TransactionsLog(
            client_ip=client_ip,
            data=str(request.data) + ' , ' + str(request.GET)
        )
        #return Response({"data": [{"message": "technical error"}], "status_code": 0},
        #                    status=status.HTTP_400_BAD_REQUEST)
        username = request.data.get('username', '')
        password = request.data.get('password', None)
        amount = request.data.get('amount', None)
        phone_number = request.data.get('phone_number', None)
        transaction_number = request.data.get('mtnTrxId', None)
        sender_gsm = request.GET.get('senderGsm', None)
        if username is None or len(str(username)) == 0:
            log.status_code = '0'
            log.message = "username is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "username is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        if password is None or len(str(password)) == 0:
            log.status_code = '0'
            log.message = "password is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "password is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        enc_password = make_password(password)
        accounts = Account.objects.filter(ip=client_ip, username=username, state=1)
        if accounts.count() == 0:
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response({"data": [{"message": "Invalid credentials"}], "status_code": 0},
                            status=status.HTTP_401_UNAUTHORIZED)
        account = accounts.first()

        if transaction_number is None or len(str(transaction_number)) == 0:
            log.status_code = '0'
            log.message = "mtnTrxId is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "mtnTrxId is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)

        if sender_gsm is None or len(str(sender_gsm)) == 0:
            log.status_code = '0'
            log.message = "senderGsm is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "senderGsm is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)



        if amount is None:
            log.status_code = '0'
            log.message = "Amount is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "Amount is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            amount = float(amount)
        except:
            log.status_code = '422'
            log.message = "Invalid amount value"
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": "Invalid amount value"}], "status_code": 422},
                            status=status.HTTP_200_OK)
        if amount <= 0:
            log.status_code = '422'
            log.message = "Amount should be positive value"
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": "Amount should be positive value"}], "status_code": 422},
                            status=status.HTTP_200_OK)
        len_trans = len(str(transaction_number))
        if len_trans == 0 or len_trans > 100:
            log.status_code = '0'
            log.message = "Invalid mtnTrxId value"
            log.response_status = '422'
            log.save()
            return Response({"data": [{"message": "Invalid mtnTrxId value"}], "status_code": 0},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if phone_number is None or len(str(phone_number)) == 0:
            log.status_code = '0'
            log.message = "phone_number is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "phone_number is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        phone_number = str(phone_number)
        if phone_number[0] == '0':
            phone_number = phone_number[1:]
        try:
            old_transactions = Transaction.objects.filter(bank_id=9, bank_ref_no=transaction_number)
            if old_transactions.count() > 0:
                log.status_code = '409'
                log.message = "There is already a transfer with the entered mtnTrxId"
                log.response_status = '200'
                log.save()
                return Response({"data": [{"message": "There is already a transfer with the entered mtnTrxId"}],
                                 "status_code": 409}, status=status.HTTP_200_OK)
            phone_number2 = '119999999'
            # user = User.objects.filter(username=username, user_type_id=6)
            customer = Customer.objects.filter(~Q(status__in=['T','C']), phone=phone_number)
            # assert user, "Username does not exist"

            prev_month = timezone.now().date() + relativedelta(months=-1)
            prev_trx = Transactions.objects.filter(~Q(mobile=phone_number), tran_ref__bank_id=MTN_BNK_ID, sender_gsm=sender_gsm, timestamp__gte=prev_month).values('mobile').distinct()  # new
            if len(prev_trx) >= 3:
                log.status_code = '410'
                log.message = "You Can not add payment for more than 3 numbers!"
                log.response_status = '200'
                log.save()
                return Response({"data": [{"message": "You Can not add payment for more than 3 numbers!"}],
                                 "status_code": 410}, status=status.HTTP_200_OK)

            assert customer, "There is no customer with the entered phone number"
            # user = user[0]
            # assert user.customer.status != 'T', "Authentication failed, customer is terminated"
            # assert user.customer.check_password(password), "Password is incorrect"
            # jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            # jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            # payload = jwt_payload_handler(user)
            # token = jwt_encode_handler(payload)
            # data = {'id': user.id, 'name': str(user.firstname_ar + ' ' + user.lastname_ar), 'token': token,
            #         'token_expiry': token_expiry(token, user)}
            credit_user = customer.first()
            source = None

            # if type(source) not in [Customer, Pos, User]:
            #     source = User.objects.get(pk=source)
            # if type(credit_user) not in [Customer, Pos, User]:
            #     credit_user = User.objects.get(pk=credit_user)
            trans_type_id = 3
            status_id = 2
            debit_id = CONFIG['COMPANY_DEBIT_ID']
            channel = 1
            # t = transfer_funds(status_id=status_id,trans_type_id=trans_type_id,debit_id=debit_id,**kwargs)
            self.create_transaction(trans_type_id, debit_id, credit_user.id,
                               status_id, channel, transaction_number, amount, phone_number, client_ip, MTN_BNK_ID, sender_gsm )
            try:
                sms_credit_transfer(credit_user, int(amount))
            except Exception as e:
                print("Unable to send SMS for MTN transfer")
                traceback.print_exc()
                pass

            data = str(amount) + ' SYP has been transferred to the subscriber account with phone number ' + str(
                phone_number)
            log.status_code = '200'
            log.message = data
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": data}], "status_code": 200}, status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            log.status_code = '422'
            log.message = e.__str__()
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": e.__str__()}], "status_code": 422}, status=status.HTTP_200_OK)



    @list_route(methods=['POST'], url_path="credit", permission_classes=[], authentication_classes=[])
    def auth(self, request):
        client_ip = get_client_ip(request)
        log = TransactionsLog(
            client_ip=client_ip,
            data=str(request.data)
        )

        username = request.data.get('username', '')
        password = request.data.get('password', None)
        amount = request.data.get('amount', None)
        phone_number = request.data.get('phone_number', None)
        transaction_number = request.data.get('mtnTrxId', None)
        if username is None or len(str(username)) == 0:
            log.status_code = '0'
            log.message = "username is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "username is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        if password is None or len(str(password)) == 0:
            log.status_code = '0'
            log.message = "password is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "password is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        enc_password = make_password(password)
        accounts = Account.objects.filter(ip=client_ip, username=username, state=1)
        if accounts.count() == 0:
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response({"data": [{"message": "Invalid credentials"}], "status_code": 0},
                            status=status.HTTP_401_UNAUTHORIZED)
        account = accounts.first()

        #if not check_password(password, account.password):
        #    log.status_code = '0'
        #    log.message = "Invalid credentials"
        #    log.response_status = '401'
        #    log.save()
        #    return Response({"data": [{"message": "Invalid credentials"}], "status_code": 0},
        #                    status=status.HTTP_401_UNAUTHORIZED)

        if transaction_number is None or len(str(transaction_number)) == 0:
            log.status_code = '0'
            log.message = "mtnTrxId is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "mtnTrxId is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)

        if amount is None:
            log.status_code = '0'
            log.message = "Amount is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "Amount is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            amount = float(amount)
        except:
            log.status_code = '422'
            log.message = "Invalid amount value"
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": "Invalid amount value"}], "status_code": 422},
                            status=status.HTTP_200_OK)
        if amount <= 0:
            log.status_code = '422'
            log.message = "Amount should be positive value"
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": "Amount should be positive value"}], "status_code": 422},
                            status=status.HTTP_200_OK)
        len_trans = len(str(transaction_number))
        if len_trans == 0 or len_trans > 100:
            log.status_code = '0'
            log.message = "Invalid mtnTrxId value"
            log.response_status = '422'
            log.save()
            return Response({"data": [{"message": "Invalid mtnTrxId value"}], "status_code": 0},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if phone_number is None or len(str(phone_number)) == 0:
            log.status_code = '0'
            log.message = "phone_number is required"
            log.response_status = '400'
            log.save()
            return Response({"data": [{"message": "phone_number is required"}], "status_code": 0},
                            status=status.HTTP_400_BAD_REQUEST)
        phone_number = str(phone_number)
        if phone_number[0] == '0':
            phone_number = phone_number[1:]
        try:
            old_transactions = Transaction.objects.filter(bank_id=9, bank_ref_no=transaction_number)
            if old_transactions.count() > 0:
                log.status_code = '409'
                log.message = "There is already a transfer with the entered mtnTrxId"
                log.response_status = '200'
                log.save()
                return Response({"data": [{"message": "There is already a transfer with the entered mtnTrxId"}],
                                 "status_code": 409}, status=status.HTTP_200_OK)
            phone_number2 = '1199951117'
            # user = User.objects.filter(username=username, user_type_id=6)
            customer = Customer.objects.filter(~Q(status__in=['T', 'C']), phone=phone_number)
            # assert user, "Username does not exist"
            assert customer, "There is no customer with the entered phone number"
            # user = user[0]
            # assert user.customer.status != 'T', "Authentication failed, customer is terminated"
            # assert user.customer.check_password(password), "Password is incorrect"
            # jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            # jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            # payload = jwt_payload_handler(user)
            # token = jwt_encode_handler(payload)
            # data = {'id': user.id, 'name': str(user.firstname_ar + ' ' + user.lastname_ar), 'token': token,
            #         'token_expiry': token_expiry(token, user)}
            credit_user = customer.first()
            source = None

            # if type(source) not in [Customer, Pos, User]:
            #     source = User.objects.get(pk=source)
            # if type(credit_user) not in [Customer, Pos, User]:
            #     credit_user = User.objects.get(pk=credit_user)
            trans_type_id = 3
            status_id = 2
            debit_id = CONFIG['COMPANY_DEBIT_ID']
            channel = 1
            # t = transfer_funds(status_id=status_id,trans_type_id=trans_type_id,debit_id=debit_id,**kwargs)
            self.create_transaction(trans_type_id, debit_id, credit_user.id,
                               status_id, channel, transaction_number, amount, phone_number, client_ip, MTN_BNK_ID)
            try:
                sms_credit_transfer(credit_user, int(amount))
            except Exception as e:
                print("Unable to send SMS for MTN transfer")
                traceback.print_exc()
                pass

            data = str(amount) + ' SYP has been transferred to the subscriber account with phone number ' + str(
                phone_number)
            log.status_code = '200'
            log.message = data
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": data}], "status_code": 200}, status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            log.status_code = '422'
            log.message = e.__str__()
            log.response_status = '200'
            log.save()
            return Response({"data": [{"message": e.__str__()}], "status_code": 422}, status=status.HTTP_200_OK)




    @list_route(methods=['GET'], url_path="category")
    def get_categories(self, request):
        try:
            categories = Category.objects.all()
            data = TicketCategorySerializer(categories, many=True).data
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': e.__str__()}, status=status.HTTP_406_NOT_ACCEPTABLE)




    @list_route(methods=['POST'], url_path="credit-payment", permission_classes=[], authentication_classes=[])
    def credit_epayment(self, request):
        client_ip = get_client_ip(request)
        log = TransactionsLog(
            client_ip=client_ip,
            data=str(request.data)
        )
        #return Response({"data": [{"message": "technical error"}], "status_code": 0},
        #                    status=status.HTTP_400_BAD_REQUEST)
        username = request.data.get('username', '')
        password = request.data.get('password', None)
        amount = request.data.get('amount', None)
        phone_number = request.data.get('phone_number', None)
        transaction_number = request.data.get('trxId', None)
        sender_gsm = request.data.get('sender_gsm', None)

        if username is None or len(str(username)) == 0:
            log.status_code = '0'
            log.message = "username is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "username is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "username is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)
        if password is None or len(str(password)) == 0:
            log.status_code = '0'
            log.message = "password is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "password is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "password is required"}], "status_code":400 },
            #                status=status.HTTP_400_BAD_REQUEST)
        accounts = Account.objects.filter(ip=client_ip, username=username, state=1)
        if accounts.count() == 0:
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response(get_body_response(None,  "Invalid credentials",401),status=status.HTTP_401_UNAUTHORIZED)
            #return Response({"data": [{"message": "Invalid credentials"}], "status_code": 401},
            #                status=status.HTTP_401_UNAUTHORIZED)
        account = accounts.first()

        if not check_password(password, account.password):
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response(get_body_response(None,  "Invalid credentials",401),status=status.HTTP_401_UNAUTHORIZED)
            #return Response({"data": [{"message": "Invalid credentials"}], "status_code": 401},
            #                status=status.HTTP_401_UNAUTHORIZED)

        if transaction_number is None or len(str(transaction_number)) == 0:
            log.status_code = '0'
            log.message = "trxId is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "trxId is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "trxId is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)

        if amount is None:
            log.status_code = '0'
            log.message = "Amount is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "amount is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "Amount is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)

        if phone_number is None or len(str(phone_number)) == 0:
            log.status_code = '0'
            log.message = "phone_number is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,"phone_number is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "phone_number is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = float(amount)
        except:
            log.status_code = '422'
            log.message = "Invalid amount value"
            log.response_status = '200'
            log.save()
            return Response(get_body_response(None,"Invalid amount value",441),status=status.HTTP_200_OK)
            #return Response({"data": [{"message": "Invalid amount value"}], "status_code": 441},
            #                status=status.HTTP_200_OK)
        if amount <= 0:
            log.status_code = '422'
            log.message = "Amount should be positive value"
            log.response_status = '200'
            log.save()
            return Response(get_body_response(None,"Amount should be positive value",442),status=status.HTTP_200_OK)
            #return Response({"data": [{"message": "Amount should be positive value"}], "status_code": 442},
            #                status=status.HTTP_200_OK)
        len_trans = len(str(transaction_number))
        if len_trans == 0 or len_trans > 100:
            log.status_code = '0'
            log.message = "Invalid trxId value"
            log.response_status = '422'
            log.save()
            return Response(get_body_response(None,"Invalid trxId value",422),status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            #return Response({"data": [{"message": "Invalid trxId value"}], "status_code": 422},
            #                status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        phone_number = str(phone_number)
        if phone_number[0] == '0':
            phone_number = phone_number[1:]

        bank_id = account.operator_type
        test_ep = False
        if bank_id == 11:
            test_ep = True
        if test_ep and (sender_gsm is None or len(str(sender_gsm)) == 0):
            log.status_code = '0'
            log.message = "sender_gsm is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,"sender_gsm is required",400),status=status.HTTP_400_BAD_REQUEST)

        try:
            bank_id = account.operator_type
            old_transactions = Transaction.objects.filter(bank_id=bank_id, bank_ref_no=transaction_number)
            if old_transactions.count() > 0:
                log.status_code = '409'
                log.message = "There is already a transfer with the entered trxId"
                log.response_status = '422'
                log.save()
                return Response(get_body_response(None,"There is already a transfer with the entered trxId",423),status=status.HTTP_422_UNPROCESSABLE_ENTITY)
                #return Response({"data": [{"message": "There is already a transfer with the entered trxId"}],
                #                 "status_code": 423}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            customer = Customer.objects.filter(~Q(status__in=['T', 'C']), phone=phone_number)
            if not customer:
                log.status_code = '422'
                log.message = "There is no customer with the entered phone number"
                log.response_status = '200'
                log.save()
                return Response(get_body_response(None,"There is no customer with the entered phone number",405),status=status.HTTP_200_OK)
                #return Response({"data": [{"message": "There is no customer with the entered phone number"}],
                #                 "status_code": 405},
                #                status=status.HTTP_200_OK)
            #phone_number2 = '119999999'
            #customer = Customer.objects.filter(phone=phone_number2, is_active=1)

            prev_month = timezone.now().date() + relativedelta(months=-1)
            prev_trx = Transactions.objects.filter(~Q(mobile=phone_number), tran_ref__bank_id=bank_id,
                sender_gsm=sender_gsm, timestamp__gte=prev_month).values('mobile').distinct()
            if test_ep and len(prev_trx) >= 2:
                log.status_code = '406'
                log.message = "You Can not add payment for more than 2 numbers during a month!"
                log.response_status = '200'
                log.save()
                return Response(get_body_response(None,"You Can not add payment for more than 2 numbers during a month!",406),status=status.HTTP_200_OK)

            credit_user = customer.first()
            source = None
            trans_type_id = 3
            status_id = 2
            debit_id = CONFIG['COMPANY_DEBIT_ID']
            channel = 1
            # t = transfer_funds(status_id=status_id,trans_type_id=trans_type_id,debit_id=debit_id,**kwargs)
            self.create_transaction(trans_type_id, debit_id, credit_user.id,
                                    status_id, channel, transaction_number, amount, phone_number, client_ip, bank_id, sender_gsm)
            try:
                sms_credit_transfer(credit_user, int(amount))
            except Exception as e:
                print("Unable to send SMS for Syriatel transfer")
                traceback.print_exc()
                pass

            data = str(amount) + ' SYP has been transferred to the subscriber account with phone number ' + str(
                phone_number)
            log.status_code = '200'
            log.message = data
            log.response_status = '200'
            log.save()
            return Response(get_body_response(None,data,200),status=status.HTTP_200_OK)
            #return Response({"data": [{"message": data}], "status_code": 200}, status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            log.status_code = '422'
            log.message = e.__str__()
            log.response_status = '200'
            log.save()
            return Response(get_body_response(None, e.__str__(),400),status=HTTP_200_OK)
            #return Response({"data": [{"message": e.__str__()}], "status_code": 400}, status=status.HTTP_200_OK)


    @list_route(methods=['POST'], url_path="inquiry", permission_classes=[], authentication_classes=[])
    def inquiry(self, request):
        client_ip = get_client_ip(request)
        log = InquiryLog(
            client_ip=client_ip,
            request_data=str(request.data)
        )

        username = request.data.get('username', '')
        password = request.data.get('password', None)
        phone_number = request.data.get('phone_number', None)
        if username is None or len(str(username)) == 0:
            log.status_code = '0'
            log.message = "username is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "username is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "username is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)
        if password is None or len(str(password)) == 0:
            log.status_code = '0'
            log.message = "password is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "password is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "password is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)
        accounts = Account.objects.filter(ip=client_ip, username=username, state=1)
        if accounts.count() == 0:
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response(get_body_response(None,  "Invalid credentials",401),status=status.HTTP_401_UNAUTHORIZED)
            #return Response({"data": [{"message": "Invalid credentials"}], "status_code": 401},
            #                status=status.HTTP_401_UNAUTHORIZED)
        account = accounts.first()

        if not check_password(password, account.password):
            log.status_code = '0'
            log.message = "Invalid credentials"
            log.response_status = '401'
            log.save()
            return Response(get_body_response(None,  "Invalid credentials",401),status=status.HTTP_401_UNAUTHORIZED)
            #return Response({"data": [{"message": "Invalid credentials"}], "status_code": 401},
            #                status=status.HTTP_401_UNAUTHORIZED)

        if phone_number is None or len(str(phone_number)) == 0:
            log.status_code = '0'
            log.message = "phone_number is required"
            log.response_status = '400'
            log.save()
            return Response(get_body_response(None,  "phone_number is required",400),status=status.HTTP_400_BAD_REQUEST)
            #return Response({"data": [{"message": "phone_number is required"}], "status_code": 400},
            #                status=status.HTTP_400_BAD_REQUEST)
        phone_number = str(phone_number)
        if phone_number[0] == '0':
            phone_number = phone_number[1:]
        try:
            customer = Customer.objects.filter(~Q(status__in=['T', 'C']), phone=phone_number)
            if not customer:
                log.status_code = '422'
                log.message = "There is no customer with the entered phone number"
                log.response_status = '200'
                log.save()
                return Response(get_body_response(None,  "There is no customer with the entered phone number",405),status=status.HTTP_200_OK)
                #return Response({"data": [{"message": "There is no customer with the entered phone number"}],
                #                 "status_code": 405},
                #                status=status.HTTP_200_OK)

            credit_user = customer.first()
            pending = Invoice.objects.filter(Q(status_id=4) |  Q(status_id=5), customer=credit_user)
            total = 0
            details = []
            for p in pending:
                details.append({'id': p.id, 'value': p.sub_total, 'discount': p.get_discount(), 'total': p.calc_total()})
                total += p.calc_total()
            balance = billing_app.calculate_user_balance(credit_user)
            total = max(0, total - balance)
            log.status_code = '200'
            log.message = ''
            log.response_status = '200'
            log.response_data = str({"message": '', 'amount_due': total})
            log.save()
            return Response(get_body_response({'amount_due': total},  "",200),status=status.HTTP_200_OK)
            #return Response({"data": [{"message": '', 'amount_due': total}], "status_code": 200},
            #                status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            log.status_code = '422'
            log.message = e.__str__()
            log.response_status = '200'
            log.save()
            return Response(get_body_response(None,  e.__str__(),400),status=status.HTTP_200_OK)
            return Response({"data": [{"message": e.__str__()}], "status_code": 400}, status=status.HTTP_200_OK)


    def logging(self, log : InquiryLog, status_code : str, message : str, response_status : str) -> None:
        log.status_code = status_code
        log.message = message
        log.response_status = response_status
        log.save()

    @list_route(methods=['POST'], url_path="payment/islamic-bank", permission_classes=[], authentication_classes=[])
    def store(self, request):

        if request.method != "POST":
            return Response(
                get_body_response(None, "Invalid request method", 400),
                status = status.HTTP_400_BAD_REQUEST
            )

        # Get bank IP address
        client_ip = get_client_ip(request)

        log = InquiryLog (
            client_ip=client_ip,
            data=str(request.data)
        )

        # Validate form data
        validator = Validator(request, log)
        valid, error = validator.validate()

        if not valid:
            return Response(
                get_body_response(None, error, 400),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        username = request.data.get('username')
        accounts = Account.objects.filter(ip=client_ip, username=username, state=1)
        if accounts.count() == 0:
            message = 'invalid credentials'
            log.log(
                status_code='0',
                message=message,
                response_status='401'
            )
            return Response(
                get_body_response(None, message, 401),
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        bankAccount = accounts.first()
        password = request.data.get('password')
        if not check_password(password, bankAccount.password):
            message = 'invalid credentials'
            log.log(
                status_code='0',
                message=message,
                response_status='401'
            )
            return Response(
                get_body_response(None, message, 401),
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        phone_number = str(request.data.get('phone_number'))
        if phone_number[0] == '0':
            phone_number = phone_number[1:]
        
        try:
            bank_id = bankAccount.operator_type
            transaction_number = request.data.get('trxId')
            old_transactions = Transaction.objects.filter(
                bank_id = bank_id,
                bank_ref_no = transaction_number
            )
            if old_transactions.count() > 0:
                message = "There is already a transfer with the entered trxId"
                log.log(
                    status_code='409',
                    message=message,
                    response_status='422'
                )
                return Response(
                    get_body_response(None,message,423),
                    status=status.HTTP_422_UNPROCESSABLE_ENTITY
                )
            
            customer = Customer.object.filter(
                ~Q(status__in=['T', 'C']),
                phone=phone_number
            )
            if not customer:
                message = "There is no customer with the entered phone number"
                log.log(
                    status_code='402',
                    message=message,
                    response_status= '200'
                )
                return Response(
                    get_body_response(None,message,405),
                    status=status.HTTP_200_OK
                )
            
            sender_gsm = request.data.get('sender_gsm', None)
            prev_month = timezone.now().date() + relativedelta(months=-1)
            prev_trx = Transactions.objects.filter(
                ~Q(mobile=phone_number),
                tran_ref__bank_id=bank_id,
                sender_gsm=sender_gsm,
                timestamp__gte=prev_month
            ).values('mobile').distinct()

            if len(prev_trx) >= 2:
                message = "You Can not add payment for more than 2 numbers during a month!"
                log.log(
                    status_code='406',
                    message=message,
                    response_status=200
                )
                return Response(
                    get_body_response(None,message,406),
                    status=status.HTTP_200_OK
                )
            
            credit_user = customer.first()
            source = None
            trans_type_id = 3
            status_id = 2
            debit_id = CONFIG['COMPANY_DEBIT_ID']
            channel = 1
            t = billing_app.transfer_funds(status_id=status_id,trans_type_id=trans_type_id,debit_id=debit_id)

            amount = float(request.data.get('amount'))
            data = str(amount) + ' SYP has been transferred to the subscriber account with phone number ' + str(
                phone_number)
            
            log.log(
                status_code= '200',
                message= data,
                response_status='200'
            )
            return Response(
                get_body_response(None,data,200),
                status=status.HTTP_200_OK
            )
        
        except Exception as e:
            traceback.print_exc()
            log.log(
                status_code= '422',
                message= e.__str__(),
                response_status= '200'
            )

            return Response(
                get_body_response(None, e.__str__(),400),
                status=status.HTTP_200_OK
            )