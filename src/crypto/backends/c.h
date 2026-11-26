/* C headers of the native crypto backends, translated by build.zig into the `c_headers`
 * module. MCL's field sizes must be defined before mcl/bn.h, as mcl_wrapper.zig expects. */
#define MCL_FP_BIT 384
#define MCL_FR_BIT 256
#include <blst.h>
#include <mcl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
