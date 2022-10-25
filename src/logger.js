//TODO: make a bracketing system to surround the message with cool | Things |

module.exports = class Logger {
    constructor (options) {
        this.options = options;
        this.options.debug = this.options.debug || false;
    }

    debug(message, fn) {
        if (this.options.debug) {
            this.log(message, fn);
        }
    }

    error(message, fn) {
        this.log(message, fn);
    }

    log(message, fn) {
        if (fn == null) {
            console.log(message);
        } else {
            console.log(`${message} \n${fn}`);
        }
    }
}
