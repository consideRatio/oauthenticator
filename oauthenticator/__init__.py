# include github, bitbucket, google here for backward-compatibility
# don't add new oauthenticators here.
from .oauth2 import *
from .github import *
from .bitbucket import *
from .microsoft import *
from .google import *
from .cilogon import *

from ._version import __version__, version_info
