"""
KaamSetu backend additions (Django REST Framework).
I could not see your existing models, so the three functions marked TODO must be
connected to your own Worker / Business models and token creation.

URLs to add:
  path('api/auth/otp/send/',   otp_send)
  path('api/auth/otp/verify/', otp_verify)
  path('api/billing/link/',    billing_link)
  path('api/razorpay/webhook/', razorpay_webhook)

settings.py (put secrets in environment variables, never in code):
  MSG91_AUTH_KEY, MSG91_TEMPLATE_ID   (India needs a DLT-registered SMS template)
  RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
  CACHES = a shared cache (Redis) so OTP limits work across servers
"""
import hashlib, hmac, json, re, secrets
import requests
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

PHONE = re.compile(r'^[6-9]\d{9}$')
PLAN_PRICE = {'Starter': 499, 'Professional': 999}  # rupees, must match the website


def _hash(phone, otp):
    return hmac.new(settings.SECRET_KEY.encode(), f'{phone}:{otp}'.encode(), hashlib.sha256).hexdigest()


def send_sms(phone, otp):
    # MSG91 OTP API. Replace with your provider (Twilio, Fast2SMS, Firebase...).
    requests.post('https://control.msg91.com/api/v5/otp', timeout=10,
                  params={'template_id': settings.MSG91_TEMPLATE_ID, 'mobile': '91' + phone,
                          'authkey': settings.MSG91_AUTH_KEY, 'otp': otp})


@api_view(['POST'])
@permission_classes([AllowAny])
def otp_send(request):
    phone = str(request.data.get('phone', ''))
    if not PHONE.match(phone):
        return Response({'detail': 'Enter a valid 10-digit mobile number.'}, status=400)
    if cache.get(f'otp:wait:{phone}'):
        return Response({'detail': 'Please wait 30 seconds before asking for a new OTP.'}, status=429)
    sent = cache.get(f'otp:count:{phone}', 0)
    if sent >= 5:
        return Response({'detail': 'Too many OTP requests. Try again in an hour.'}, status=429)
    otp = f'{secrets.randbelow(10**6):06d}'
    cache.set(f'otp:{phone}', _hash(phone, otp), 300)   # valid 5 minutes, stored hashed
    cache.set(f'otp:tries:{phone}', 0, 300)
    cache.set(f'otp:wait:{phone}', 1, 30)
    cache.set(f'otp:count:{phone}', sent + 1, 3600)
    send_sms(phone, otp)
    return Response({'detail': 'sent'})


@api_view(['POST'])
@permission_classes([AllowAny])
def otp_verify(request):
    d = request.data
    phone, otp, role, purpose = str(d.get('phone', '')), str(d.get('otp', '')), d.get('role'), d.get('purpose')
    if not (PHONE.match(phone) and re.fullmatch(r'\d{6}', otp) and role in ('worker', 'biz')):
        return Response({'detail': 'Invalid request.'}, status=400)
    tries = cache.get(f'otp:tries:{phone}', 0)
    stored = cache.get(f'otp:{phone}')
    if not stored or tries >= 5:
        return Response({'detail': 'OTP expired. Please request a new one.'}, status=400)
    if not hmac.compare_digest(stored, _hash(phone, otp)):
        cache.set(f'otp:tries:{phone}', tries + 1, 300)
        return Response({'detail': 'Wrong OTP. Please try again.'}, status=400)
    cache.delete(f'otp:{phone}')                          # one-time use
    user = find_account(phone, role)                       # TODO
    if purpose == 'login' and not user:
        return Response({'detail': 'No account with this number. Please sign up first.'}, status=400)
    if purpose == 'register':
        if user:
            return Response({'detail': 'This number is already registered. Please log in.'}, status=400)
        user = create_account(role, phone, d)              # TODO
    return Response(token_payload(user))                   # TODO: {'token','role','profile':{'id','name'}}


def find_account(phone, role):
    raise NotImplementedError('Return your user/profile for this phone and role, or None.')


def create_account(role, phone, data):
    raise NotImplementedError('Create the Worker/Business using data name, city, skill (worker only).')


def token_payload(user):
    raise NotImplementedError("Return {'token': ..., 'role': ..., 'profile': {'id': ..., 'name': ...}}.")


# ---------- Razorpay ----------
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def billing_link(request):
    plan = request.data.get('plan')
    if plan not in PLAN_PRICE:
        return Response({'detail': 'Unknown plan.'}, status=400)
    biz = request.user.business                             # TODO: adjust to your model
    r = requests.post('https://api.razorpay.com/v1/payment_links', timeout=15,
                      auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET),
                      json={'amount': PLAN_PRICE[plan] * 100, 'currency': 'INR',
                            'description': f'KaamSetu {plan} plan, 1 month',
                            'reference_id': f'biz{biz.id}-{plan}-{secrets.token_hex(4)}',
                            'notes': {'business_id': str(biz.id), 'plan': plan},
                            'notify': {'sms': False, 'email': False}})
    if r.status_code >= 400:
        return Response({'detail': 'Could not create the payment link. Please try again.'}, status=502)
    return Response({'short_url': r.json()['short_url']})


@csrf_exempt
def razorpay_webhook(request):
    # In the Razorpay dashboard: Settings > Webhooks > add this URL, event "payment_link.paid".
    sig = request.headers.get('X-Razorpay-Signature', '')
    good = hmac.new(settings.RAZORPAY_WEBHOOK_SECRET.encode(), request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good):
        return HttpResponse(status=400)
    ev = json.loads(request.body)
    if ev.get('event') == 'payment_link.paid':
        pl = ev['payload']['payment_link']['entity']
        pay_id = ev['payload']['payment']['entity']['id']
        notes = pl.get('notes', {})
        if not cache.add(f'rzp:{pay_id}', 1, 86400 * 7):    # ignore repeated deliveries
            return HttpResponse(status=200)
        activate_plan(int(notes['business_id']), notes['plan'], PLAN_PRICE[notes['plan']], pay_id)  # TODO
    return HttpResponse(status=200)


def activate_plan(business_id, plan, amount, payment_id):
    raise NotImplementedError('Set business.plan and credits, and create a paid invoice with payment_id.')
