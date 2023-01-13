# Paycek

This is an official package for the Paycek payment processor. The documentation provided in code explains only minor implementation details.

For in depth information about endpoints, fields and more, read our [API Documentation](https://paycek.io/api/docs).

## Quick Start

### Installation

Install package with pip.

```shell
pip install paycek
```

### Initialization

Under account settings you’ll find your API key and secret. Initialize a paycek instance.

```python
from paycek import Paycek

paycek = Paycek(
    api_key='<api_key>',
    api_secret='<api_secret>'
)
```

### Usage

```python
payment = paycek.get_payment('<payment_code>')
```