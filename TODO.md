//YAPTIM!
let originalPayload = fromString(params.linkedBlock, "base64pad");
console.log("originalPayload", dagCBOR.decode(originalPayload))

import * as dagCBOR from '@ipld/dag-cbor';
import { fromString } from 'uint8arrays/from-string';
