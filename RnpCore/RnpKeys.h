#pragma once
#include <string>

class RnpKeys
{
public:
  bool can_encrypt = false, invalid = false;
  std::string keyid, name, email, foundUsingPattern;
  int validity;
  std::string getKeyStr(){
    return keyid + " # " + name + " <" + email + ">";
  }
};
