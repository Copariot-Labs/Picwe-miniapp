
network = 'polygon'
net_type = 'mainnet'

# 定义网络参数
networks = {
    'polygon': {
        'mainnet': {
            'CHAIN_NAME': 'polygon_mainnet',
            'TX_BASE_URL': 'https://polygonscan.com/tx/',
            'TOKEN': ',
            'simple_pUSDT_address': '',
            'pUSDT_address': '',
        },
        'testnet': {
            'CHAIN_NAME': 'polygon_mumbai',
            'TX_BASE_URL': 'https://mumbai.polygonscan.com/tx/',
            'TOKEN': '',
            'simple_pUSDT_address': '',
            'pUSDT_address': '',
        }
    },
    'ethereum': {
        'mainnet': {
            'CHAIN_NAME': 'ethereum_mainnet',
            'TX_BASE_URL': 'https://etherscan.io/tx/',
            'TOKEN': 'YOUR_ETHEREUM_MAINNET_TOKEN',
            'simple_pUSDT_address': 'YOUR_ETHEREUM_MAINNET_SIMPLE_PUSDT_ADDRESS',
            'pUSDT_address': 'YOUR_ETHEREUM_MAINNET_PUSDT_ADDRESS',
        },
        'testnet': {
            'CHAIN_NAME': 'ethereum_goerli',
            'TX_BASE_URL': 'https://goerli.etherscan.io/tx/',
            'TOKEN': 'YOUR_ETHEREUM_GOERLI_TOKEN',
            'simple_pUSDT_address': 'YOUR_ETHEREUM_GOERLI_SIMPLE_PUSDT_ADDRESS',
            'pUSDT_address': 'YOUR_ETHEREUM_GOERLI_PUSDT_ADDRESS',
        }
    }
}

params = networks[network][net_type]
CHAIN_NAME = params['CHAIN_NAME']
TX_BASE_URL = params['TX_BASE_URL']
TOKEN = params['TOKEN']
simple_pUSDT_address = params['simple_pUSDT_address']
pUSDT_address = params['pUSDT_address']

PR = ''
