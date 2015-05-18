#include "rfc3986.hh"

#include <boost/fusion/include/boost_tuple.hpp>
#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include "rfc2234.hh"

namespace st = boost::spirit;
namespace px = boost::phoenix;

namespace ka = st::karma;
namespace qi = st::qi;

using namespace qi::labels;

namespace corax   {
namespace rfc3986 {
namespace detail  {

template<class I>
class parser : public qi::grammar<I, uri()>, rfc2234::core<I> {
  typedef char char_type;
  typedef I    iterator;

  typedef rfc2234::core<iterator> core;
  typedef std::string             string;

  qi::rule<iterator, uri()>                  URI, URI_reference;
  qi::rule<iterator, detail::relative_ref()> relative_ref;
  qi::rule<iterator, hierarchical()>         hier_part;
  qi::rule<iterator, detail::authority()>    authority;
  qi::rule<iterator, detail::user_data()>    user_data;
  qi::rule<iterator, std::uint16_t()>        port;
  qi::rule<iterator, string()>
    scheme, user, password, host, IP_literal, IPvFuture, IPv6address, h16, ls32,
    IPv4address, dec_octet, reg_name, path, path_abempty, path_absolute,
    path_noscheme, path_rootless, path_empty, segment, segment_nz,
    segment_nz_nc, query, fragment, pct_encoded, pchar;
  qi::rule<iterator, char_type()> unreserved, reserved, gen_delims, sub_delims;

public:
  parser() : parser::base_type(URI_reference) {
    auto& c = qi::char_;
    auto& r = qi::repeat;
    auto& s = qi::string;

    URI %= scheme >> ':' >> relative_ref;

    hier_part =
      (
        "//" >>
        authority   [px::at_c<0>(_val) = _1] >>
        path_abempty[px::at_c<1>(_val) = _1]
      ) |
      (path_absolute | path_rootless | path_empty)[px::at_c<1>(_val) = _1];

    URI_reference = (URI[_val = _1] | relative_ref[px::at_c<1>(_val) = _1]);

    relative_ref %= hier_part >> -('?' >> query) >> -('#' >> fragment);

    scheme %=
      core::alpha >> *(core::alpha | core::digit | c('+') | c('-') | c('.'));

    authority %= -(user_data >> '@') >> host >> -(":" >> port);

    user_data %= user >> -(':' >> password);

    user %= *(unreserved | pct_encoded | sub_delims);

    password %= *(unreserved | pct_encoded | sub_delims | c(':'));

    host %= (IP_literal | IPv4address | reg_name);

    port = *(core::digit[_val *= 10][_val += _1 - '0']);

    IP_literal %= c('[') >> (IPv6address | IPvFuture) >> c(']');

    IPvFuture %=
      c('v') >> +core::hexdig >> c('.') >> +(unreserved | sub_delims | c(':'));

    //FIXME Rule doesn't work (i.e. for ldap://[2001:db8::7]/c=GB?objectClass?one)
    IPv6address %=                                   r(6)[h16 >> c(':')] >> ls32 |
                                          s("::") >> r(5)[h16 >> c(':')] >> ls32 |
                                 -h16  >> s("::") >> r(4)[h16 >> c(':')] >> ls32 |
      -(r(0, 1)[h16 >> c(':')] >> h16) >> s("::") >> r(3)[h16 >> c(':')] >> ls32 |
      -(r(0, 2)[h16 >> c(':')] >> h16) >> s("::") >> r(2)[h16 >> c(':')] >> ls32 |
      -(r(0, 3)[h16 >> c(':')] >> h16) >> s("::") >>      h16 >> c(':')  >> ls32 |
      -(r(0, 4)[h16 >> c(':')] >> h16) >> s("::")                        >> ls32 |
      -(r(0, 5)[h16 >> c(':')] >> h16) >> s("::")                        >>  h16 |
      -(r(0, 6)[h16 >> c(':')] >> h16) >> s("::");

    h16 %= r(1, 4)[core::hexdig];

    ls32 %= (h16 >> c(':') >> h16) | IPv4address;

    IPv4address %= dec_octet >> r(3)[c('.') >> dec_octet];

    dec_octet %=               c('0', '9') |
                c('1', '9') >> c('0', '9') |
      c('1') >> c('0', '9') >> c('0', '9') |
      c('2') >> c('0', '4') >> c('0', '9') |
      c('2') >> c('5')      >> c('0', '5');

    reg_name %= *(unreserved | pct_encoded | sub_delims);

    path %=
      path_abempty | path_absolute | path_noscheme | path_rootless | path_empty;

    path_abempty %= *(c('/') >> segment);

    path_absolute %= c('/') >> -(segment_nz >> *(c('/') >> segment));

    path_noscheme %= segment_nz_nc >> *(c('/') >> segment);

    path_rootless %= segment_nz >> *(c('/') >> segment);

    path_empty %= qi::eps;

    segment %= *pchar;

    segment_nz %= +pchar;

    segment_nz_nc %= +(unreserved | pct_encoded | sub_delims | c('@'));

    pchar %= unreserved | pct_encoded | sub_delims | c(':') | c('@');

    query %= *(pchar | c('/') | c('?'));

    fragment %= *(pchar | c('/') | c('?'));

    pct_encoded %= qi::lit('%') >> core::hexdig >> core::hexdig;

    unreserved %= core::alpha | core::digit | c('-') | c('.') | c('_') | c('~');

    reserved %= gen_delims | sub_delims;

    gen_delims %= c(':') | c('/') | c('?') | c('#') | c('[') | c(']') | c('@');

    sub_delims %=
      c('!') | c('$') | c('&') | c('(') | c(')') |
      c('*') | c('+') | c(',') | c(';') | c('=') | c('\'');
  }; //parser
}; //parser

template <typename I>
class generator : public ka::grammar<I, uri()> {
  typedef I           iterator;
  typedef std::string string;

  ka::rule<iterator, uri()>                  URI, URI_reference;
  ka::rule<iterator, detail::relative_ref()> relative_ref;
  ka::rule<iterator, detail::hierarchical()> hier_part;
  ka::rule<iterator, detail::authority()>    authority;
  ka::rule<iterator, detail::user_data()>    user_data;
  ka::rule<iterator, string()>
    scheme, user, password, host, path, query, fragment;
  ka::rule<iterator, std::uint16_t()>        port;

public:
  generator() : generator::base_type(URI_reference) {
    URI_reference = -(scheme << ':') << relative_ref;

    relative_ref = hier_part << -('?' << query) << -('#' << fragment);

    hier_part = -("//" << authority) << path;

    authority = -(user_data << '@') << host << -(':' << port);

    user_data = user << -(':' << password);

    scheme = user = password = host = path = query = fragment = ka::string;

    port = ka::uint_;
  }; //generator
}; //generator

}; //detail

std::istream& operator >> (std::istream& source, uri& uri) {
  static const detail::parser<st::istream_iterator> parser;

  boost::spirit::istream_iterator begin{source}, end;

  if(!qi::parse(begin, end, parser, uri.m_impl) || begin != end)
    throw std::logic_error("invalid URI");

  return source;
};

std::ostream& operator << (std::ostream& sink, const uri& uri) {
  static detail::generator<st::ostream_iterator> generator;

  ka::generate(boost::spirit::ostream_iterator{sink}, generator, uri.m_impl);

  return sink;
};

}; //rfc3986
}; //corax
