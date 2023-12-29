#include "RnpCoreInterface.h"
#include "RnpCoreBal.h"
std::unique_ptr<RnpCoreInterface> getRnpCoreInterface(){
    return std::make_unique<RnpCoreBal>();
}