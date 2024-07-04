#!/usr/bin/python

# Requirements:
# Install the necessary libraries using pip:
# pip install boto3 requests beautifulsoup4 configparser python-dateutil

import sys
import boto3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import datetime
from dateutil.tz import tzutc
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

##########################################################################
# المتغيرات

# region: المنطقة الافتراضية التي سيتصل بها هذا السكريبت
# لجميع استدعاءات API
region = 'us-west-2'

# output format: تنسيق إخراج AWS CLI الذي سيتم تكوينه في
# الملف الشخصي SAML (يؤثر على استدعاءات CLI اللاحقة)
outputformat = 'json'

# awsconfigfile: الملف الذي سيخزن فيه هذا السكريبت
# بيانات الاعتماد المؤقتة ضمن الملف الشخصي SAML
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: ما إذا كان يتم التحقق الصارم من الشهادة
# أم لا، يجب استخدام False فقط للتطوير/الاختبار
sslverification = True

# idpentryurl: URL البدء الذي يبدأ عملية المصادقة.
idpentryurl = 'https://sts.company.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

# قم بإلغاء التعليق لتمكين تصحيح الأخطاء على مستوى منخفض
# logging.basicConfig(level=logging.DEBUG)

# اكتب رمز AWS STS في ملف بيانات اعتماد AWS
home = expanduser("~")
filename = home + awsconfigfile
##########################################################################

def get_sts_temp_keys(role_arn, principal_arn, assertion):
    # استخدم الادعاء للحصول على رمز AWS STS باستخدام Assume Role with SAML
    stsclient = boto3.client('sts')
    token = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)

    # اقرأ ملف التكوين الحالي
    config = configparser.RawConfigParser()
    config.read(filename)

    # ضع بيانات الاعتماد في قسم محدد بـ SAML بدلاً من الكتابة فوق
    # بيانات الاعتماد الافتراضية
    if not config.has_section('saml'):
        config.add_section('saml')

    config.set('saml', 'output', outputformat)
    config.set('saml', 'region', region)
    config.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])

    # اكتب ملف التكوين المحدث
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    return token

# الحصول على الاسم المستعار للحساب
def get_account_alias():
    session = boto3.Session(profile_name='saml')
    iamclient = session.client('iam')
    response = iamclient.list_account_aliases()
    if len(response['AccountAliases']) > 0:
        return response['AccountAliases'][0]
    else:
        return 'لم يتم العثور على اسم مستعار للحساب.'

def main():
    # احصل على بيانات الاعتماد الفيدرالية من المستخدم
    print("اسم المستخدم:", end=' ')
    username = input()
    password = getpass.getpass()
    print('')

    # ابدأ معالج الجلسة
    session = requests.Session()

    # الحصول على الادعاء SAML برمجيًا
    # افتح URL البدء IdP واتبع جميع تحويلات HTTP 302، واحصل
    # على صفحة تسجيل الدخول الناتجة
    formresponse = session.get(idpentryurl, verify=sslverification)
    # التقط URL إرسال النموذج idpauthformsubmiturl، وهو URL النهائي بعد جميع تحويلات 302
    idpauthformsubmiturl = formresponse.url

    # تحليل الاستجابة واستخراج جميع القيم اللازمة
    # من أجل بناء قاموس من جميع قيم النموذج التي يتوقعها IdP
    formsoup = BeautifulSoup(formresponse.text.encode('utf8'), 'html.parser')
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "user" in name.lower():
            # تخمين متعلم أن هذا هو الحقل الصحيح لاسم المستخدم
            payload[name] = username
        elif "email" in name.lower():
            # بعض IdPs تصف أيضًا حقل اسم المستخدم كـ 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # تخمين متعلم أن هذا هو الحقل الصحيح لكلمة المرور
            payload[name] = password
        else:
            # ببساطة املأ المعلمة بالقيمة الموجودة (تلتقط الحقول المخفية في نموذج تسجيل الدخول)
            payload[name] = value

    # بعض IdPs لا تعين صراحة إجراء النموذج، ولكن إذا كان واحدًا معينًا فيجب علينا
    # بناء URL إرسال النموذج idpauthformsubmiturl بدمج المخطط واسم المضيف
    # من URL الإدخال مع هدف إجراء النموذج
    # إذا لم يكن هناك علامة إجراء، فإننا نتمسك فقط بـ
    # idpauthformsubmiturl أعلاه
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        loginid = inputtag.get('id')
        if action and loginid == "loginForm":
            parsedurl = urlparse(idpentryurl)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

    # تنفيذ إرسال نموذج تسجيل الدخول IdP بالبيانات السابقة
    response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification)

    # الكتابة فوق وحذف متغيرات بيانات الاعتماد، فقط للأمان
    username = 'khaledmohamedradwan'
    password = 'R@DwaN$9$9$khaled'
    del username
    del password

    # فك تشفير الاستجابة واستخراج الادعاء SAML
    soup = BeautifulSoup(response.text.encode('utf8'), 'html.parser')
    assertion = ''

    # البحث عن سمة SAMLResponse في علامة الإدخال (تحديدًا عن طريق
    # تحليل خطوط التصحيح أعلاه)
    for inputtag in soup.find_all('input'):
        if inputtag.get('name') == 'SAMLResponse':
            assertion = inputtag.get('value')

    # هناك حاجة إلى معالجة أخطاء أفضل للاستخدام الإنتاجي.
    if assertion == '':
        print('الاستجابة لم تحتوي على ادعاء SAML صالح')
        sys.exit(0)

    # تحليل الادعاء المسترجع واستخراج الأدوار المصرح بها
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # لاحظ أن تنسيق قيمة السمة يجب أن يكون role_arn,principal_arn
    # ولكن العديد من المدونات تسردها كـ principal_arn,role_arn لذا دعنا نعكس
    # إذا لزم الأمر
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    # إذا كان لدي أكثر من دور واحد، فاسأل المستخدم عن الدور الذي يريده،
    # وإلا فقط استمر
    if len(awsroles) > 1:
        i = 0
        print("يرجى اختيار الدور الذي تود افتراضه:")
        for awsrole in awsroles:
            role_arn = awsroles[i].split(',')[0]
            principal_arn = awsroles[i].split(',')[1]
            get_sts_temp_keys(role_arn, principal_arn, assertion)
            alias = get_account_alias()
            print('[{}]: {} -> {}'.format(i, awsrole.split(',')[0], alias))
            i += 1

        print("الاختيار: ", end=' ')
        selectedroleindex = input()

        # فحص أساسي للمدخلات
        if int(selectedroleindex) > (len(awsroles) - 1):
            print('لقد اخترت فهرس دور غير صالح، يرجى المحاولة مرة أخرى')
            sys.exit(0)

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    token = get_sts_temp_keys(role_arn, principal_arn, assertion)

    # أعط المستخدم بعض المعلومات الأساسية حول ما حدث للتو
    print('\n\n----------------------------------------------------------------')
    print('تم تخزين زوج مفاتيح الوصول الجديد الخاص بك في ملف تكوين AWS {0} ضمن الملف الشخصي saml.'.format(filename))
    print('لاحظ أنه سينتهي صلاحيته في {0}.'.format(token['Credentials']['Expiration']))
    print('بعد هذا الوقت، يمكنك إعادة تشغيل هذا السكريبت بأمان لتحديث زوج مفاتيح الوصول الخاص بك.')
    print('لاستخدام بيانات الاعتماد هذه، قم باستدعاء AWS CLI مع خيار --profile (مثال: aws --profile saml ec2 describe-instances).')
    print('----------------------------------------------------------------\n\n')

    # استخدم رمز AWS STS لسرد جميع دلوات S3
    session = boto3.Session(profile_name='saml')
    s3client = session.client('s3')
    response = s3client.list_buckets()
    print('مثال بسيط على API لسرد جميع دلوات S3:')
    print(response)

if __name__ == "__main__":
    main()
