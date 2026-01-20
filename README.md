# migate 

**migate** is a simplified Xiaomi authentication gateway for Python projects

## Installation
```bash
pip install migate
```

Or in pyproject.toml:

```toml
dependencies = [
    "migate"
]

```

## Usage

```python
import migate

service_id = ''

service_param = {"sid": service_id}

# Required for some service IDs like "unlockApi"
# service_param["checkSafeAddress"] = True

pass_token = migate.get_passtoken(service_param)
# pass_token returns: {"deviceId", "passToken", "userId"}

# ___

service = migate.get_service(pass_token, service_id)
# {'servicedata': {'nonce', 'ssecurity', 'cUserId', 'psecurity'}, 'cookies': {'serviceToken/popRunToken/new_bbs_serviceToken' ...}}
print(service)
```

returns: {'servicedata': {'nonce', 'ssecurity', 'cUserId', 'psecurity'}, 'cookies': {'serviceToken/popRunToken/new_bbs_serviceToken' ...}}

___

<div align="center">

![MIT License](https://img.shields.io/badge/License-MIT-green.svg)

</div>