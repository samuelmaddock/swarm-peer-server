const yargs = require('yargs')
const swarm = require('../index.js')

yargs
    .demand(1)
    .command(
        'listen [keyfile]',
        'Create swarm server listening at the public key hash.',
        {},
        args => {
            // todo
            swarm.listen({}, (socket) => {
                
            })
        }
    )
    .command(
        'connect [desthash] [keyfile]',
        'Connect to swarm server at the given hash.',
        {},
        args => {
            // todo
            swarm.connect({})
        }
    )
    .help()
    .strict().argv