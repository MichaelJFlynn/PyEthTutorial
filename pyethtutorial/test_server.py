from devp2p.app import BaseApp
from devp2p.discovery import NodeDiscovery
from devp2p import slogging
slogging.configure(config_string=':debug')

app = BaseApp()

config = app.config
config.update({
    'discovery' : {
        'listen_host' : '0.0.0.0',
        'listen_port' : 30303,
        'bootstrap_nodes' : [
            #'enode://' + '00'*64 + '@5.1.83.226:30303'
        ]
    },
    'node' : {
        'privkey_hex' : '65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b'
    }
})

NodeDiscovery.register_with_app(app)

app.start()
