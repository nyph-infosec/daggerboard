import ldap, pyaes, logging, environ

from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

from .models import Ldap


env = environ.Env()
environ.Env.read_env()

logging.basicConfig(filename=env('LOGPATH'), filemode='a', format='%(levelname)s - %(asctime)s - %(message)s', level=logging.INFO)

class GroupLDAPBackend(LDAPBackend):
  '''
  Extended LDAPBackend from django-auth-ldap to apply values from 
  LDAP configuration in admin panel.

  Key must be 32 bytes for AES encryption
  '''
  
  try:
    ldap_admin = Ldap.objects.values()
    key = env('LDAP_BIND_PROTECTION')
    key_encoded = key.encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(key_encoded)
    encrypt_formatted = (ldap_admin[0].get('bind_password')[2:][:-1]).encode()
    esc_unicode_format = encrypt_formatted.decode('unicode-escape').encode('ISO-8859-1')
    bind_pass = aes.decrypt(esc_unicode_format).decode('utf-8')
  except:
    logging.info('Unable to access ldap server bind password.')

  try:
    default_settings = {
      "SERVER_URI": ldap_admin[0].get('server_uri'),
      "BIND_DN": ldap_admin[0].get('bind_dn'),
      "BIND_PASSWORD": bind_pass,
      "USER_SEARCH": LDAPSearch(
        ldap_admin[0].get('user_search'),
        ldap.SCOPE_SUBTREE,
        "(sAMAccountName=%(user)s)"
      ),
      "GROUP_SEARCH": LDAPSearch(
          ldap_admin[0].get('group_search'),
          ldap.SCOPE_SUBTREE,
          "(objectClass=groupOfNames)",
      ),
      "GROUP_TYPE": GroupOfNamesType(
          name_attr=ldap_admin[0].get('auth_ldap_group_type')
      ),
      "AUTH_LDAP_FIND_GROUP_PERMS":True,
      "AUTH_LDAP_MIRROR_GROUPS":'True',
      "REQUIRE_GROUP": ldap_admin[0].get('auth_ldap_require_group'),
      #"START_TLS": True,
      "ALWAYS_UPDATE_USER":True,
      "FIND_GROUP_PERMS":True,
      "CACHE_TIMEOUT":3600
    }
  except:
    logging.info('Unable to query LDAP settings from database. Settings are null or incorrect. Defaulting to local authentication.')
    default_settings = {
      "SERVER_URI": "",
      "BIND_DN": "",
      "BIND_PASSWORD": "",
      "USER_SEARCH": "",
      "GROUP_SEARCH": "",
      "GROUP_TYPE": "",
      "AUTH_LDAP_FIND_GROUP_PERMS": True,
      "AUTH_LDAP_MIRROR_GROUPS": 'True',
      "REQUIRE_GROUP": "",
      # "START_TLS": True,
      "ALWAYS_UPDATE_USER": True,
      "FIND_GROUP_PERMS": True,
      "CACHE_TIMEOUT": 3600
    }

  def authenticate_ldap_user(self, ldap_user: _LDAPUser, password: str):
    ldap_admin = Ldap.objects.values()
    try:
      check_server_uri = ldap_admin[0].get('server_uri')
      if check_server_uri is '':
        logging.info(f"ldap not configured: {e}")
        return None
      else:
        user = ldap_user.authenticate(password)
        return user
    except Exception as e:
      logging.error(f"ldap not configured: {e}")
      return None
    

