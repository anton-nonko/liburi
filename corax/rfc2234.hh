#ifndef CORAX_RFC2234_HH
#define CORAX_RFC2234_HH

#include <boost/spirit/include/qi.hpp>

namespace corax   {
namespace rfc2234 {

template<class I>
class core {
  typedef char char_type;
  typedef I    iterator;

protected:
  boost::spirit::qi::rule<iterator, char_type()>
    alpha,  /// 'A'-'Z' / 'a'-'z'
    bit,    /// '0' / '1'
    char_,  /// any 7-bit US-ASCII character, excluding 0
    cr;     /// carriage return

  boost::spirit::qi::rule<iterator, std::vector<char_type>()>
    crlf;   /// Internet standard newline

  boost::spirit::qi::rule<iterator, char_type()>
    ctl,    /// controls
    digit,  /// '0'-'9'
    dquote, /// '"' (Double Quote)
    hexdig, /// '0'-'9' / 'A'-'F' / 'a'-'f'
    htab,   /// horizontal tab
    lf;     /// linefeed

  boost::spirit::qi::rule<iterator, std::vector<char_type>()>
    lwsp;   /// linear white space (past newline)

  boost::spirit::qi::rule<iterator, char_type()>
    octet,  /// 8 bits of data
    sp,     /// space
    vchar,  /// visible (printing) characters
    wsp;    /// white space

  core() {
    namespace qi = boost::spirit::qi;

    auto& c = boost::spirit::qi::char_;

    alpha  %= c(0x41, 0x5A) | c(0x61, 0x7A);

    bit    %= c(0x30) | c(0x31);

    char_  %= c(0x01, 0x7F);

    cr     %= c(0x0D);

    crlf   %= cr >> lf;

    ctl    %= c(0x00, 0x1F) | c(0x7F);

    digit  %= c(0x30, 0x39);

    dquote %= c(0x22);

    hexdig %= digit | c(0x41, 0x46) | c(0x61, 0x66);

    htab   %= c(0x09);

    lf     %= c(0x0A);

    lwsp   %= *(wsp | (crlf >> wsp));

    octet  %= c(0x00, 0xFF);

    sp     %= c(0x20);

    vchar  %= c(0x21, 0x7E);

    wsp    %= sp | htab;
  }; //core
}; //core

}; //rfc2234
}; //corax

#endif //#ifndef CORAX_RFC2234_HH
