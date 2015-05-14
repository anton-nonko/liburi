#ifndef CORAX_RFC3986_HH
#define CORAX_RFC3986_HH

#include <cstdint>
#include <boost/fusion/adapted/struct/adapt_struct.hpp>
#include <boost/fusion/include/adapt_struct.hpp>
#include <boost/fusion/include/boost_tuple.hpp>
#include <boost/spirit/include/phoenix_core.hpp>
#include <boost/spirit/include/phoenix_operator.hpp>
#include <boost/spirit/include/phoenix_fusion.hpp>
#include <boost/spirit/include/phoenix_stl.hpp>
#include <boost/spirit/include/phoenix_object.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/qi_core.hpp>
#include <boost/tuple/tuple.hpp>
#include "rfc2234.hh"

namespace corax   {
namespace rfc3986 {

struct uri_data {
  boost::optional<std::string>   scheme;
  boost::optional<std::string>   user;
  boost::optional<std::string>   password;
  boost::optional<std::string>   host;
  boost::optional<unsigned>      port;
  boost::optional<std::string>   path;
  boost::optional<std::string>   query;
  boost::optional<std::string>   fragment;
}; //uri_data

}; //rfc3986
}; //corax

BOOST_FUSION_ADAPT_STRUCT(
  corax::rfc3986::uri_data,
  (boost::optional<std::string>, scheme)   // 0
  (boost::optional<std::string>, user)     // 1
  (boost::optional<std::string>, password) // 2
  (boost::optional<std::string>, host)     // 3
  (boost::optional<unsigned>,    port)     // 4
  (boost::optional<std::string>, path)     // 5
  (boost::optional<std::string>, query)    // 6
  (boost::optional<std::string>, fragment) // 7
)

namespace corax   {
namespace rfc3986 {

template<class I>
struct parser :
  boost::spirit::qi::grammar<I, uri_data()>, rfc2234::core<I>
{
private:
  typedef char char_type;
  typedef I    iterator;

  typedef rfc2234::core<iterator> core;
  typedef uri_data                data;
  typedef std::string             string;

  typedef
    boost::tuple<
      boost::optional<string>,
      boost::optional<string>,
      boost::optional<string>,
      boost::optional<unsigned>,
      boost::optional<string>
    >
    hier_part_data;

  typedef
    boost::tuple<
      boost::optional<string>,
      boost::optional<string>,
      boost::optional<string>,
      boost::optional<unsigned>
    >
    authority_data;

  boost::spirit::qi::rule<iterator, data()>
    URI,
    URI_reference,
    relative_ref;
  boost::spirit::qi::rule<iterator, hier_part_data()>
    hier_part;
  boost::spirit::qi::rule<iterator, authority_data()>
    authority;
  boost::spirit::qi::rule<iterator, string()>
    scheme,
    user,
    password,
    host;
  boost::spirit::qi::rule<iterator, unsigned()>
    port;
  boost::spirit::qi::rule<iterator, string()>
    IP_literal,
    IPvFuture,
    IPv6address,
    h16,
    ls32,
    IPv4address,
    dec_octet,
    reg_name,
    path,
    path_abempty,
    path_absolute,
    path_noscheme,
    path_rootless,
    path_empty,
    segment,
    segment_nz,
    segment_nz_nc,
    query,
    fragment,
    pct_encoded,
    pchar;
  boost::spirit::qi::rule<iterator, char_type()>
    unreserved,
    reserved,
    gen_delims,
    sub_delims;

public:
  parser() : parser::base_type(URI_reference) {
    namespace px = boost::phoenix;
    namespace qi = boost::spirit::qi;

    using namespace qi::labels;

    auto& c = boost::spirit::qi::char_;
    auto& r = boost::spirit::qi::repeat;
    auto& s = boost::spirit::qi::string;

    URI =
      scheme[px::at_c<0>(_val) = _1] >> ':' >>
      hier_part
        [px::at_c<1>(_val) = px::at_c<0>(_1)]
        [px::at_c<2>(_val) = px::at_c<1>(_1)]
        [px::at_c<3>(_val) = px::at_c<2>(_1)]
        [px::at_c<4>(_val) = px::at_c<3>(_1)]
        [px::at_c<5>(_val) = px::at_c<4>(_1)] >>
      -('?' >> query   [px::at_c<6>(_val) = _1]) >>
      -('#' >> fragment[px::at_c<7>(_val) = _1]);

    hier_part =
      (
        "//" >>
        authority
          [px::at_c<0>(_val) = px::at_c<0>(_1)]
          [px::at_c<1>(_val) = px::at_c<1>(_1)]
          [px::at_c<2>(_val) = px::at_c<2>(_1)]
          [px::at_c<3>(_val) = px::at_c<3>(_1)] >>
        path_abempty[px::at_c<4>(_val) = _1]
      ) |
      (path_absolute | path_rootless | path_empty)[px::at_c<4>(_val) = _1];

    URI_reference %=
      (
        URI          |
        relative_ref
      );

    relative_ref =
      hier_part
        [px::at_c<1>(_val) = px::at_c<0>(_1)]
        [px::at_c<2>(_val) = px::at_c<1>(_1)]
        [px::at_c<3>(_val) = px::at_c<2>(_1)]
        [px::at_c<4>(_val) = px::at_c<3>(_1)]
        [px::at_c<5>(_val) = px::at_c<4>(_1)] >>
      -('?' >> query   [px::at_c<6>(_val) = _1]) >>
      -('#' >> fragment[px::at_c<7>(_val) = _1]);

    scheme %=
      core::alpha >> *(core::alpha | core::digit | c('+') | c('-') | c('.'));

    authority =
      -(
        user[px::at_c<0>(_val) = _1] >>
        -(':' >> password[px::at_c<1>(_val) = _1]) >>
        '@'
      ) >>
      host[px::at_c<2>(_val) = _1] >>
      -(":" >> port[px::at_c<3>(_val) = _1]);

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

    pct_encoded %=
      qi::lit('%') >> core::hexdig >> core::hexdig;

    unreserved %= core::alpha | core::digit | c('-') | c('.') | c('_') | c('~');

    reserved %= gen_delims | sub_delims;

    gen_delims %= c(':') | c('/') | c('?') | c('#') | c('[') | c(']') | c('@');

    sub_delims %=
      c('!') | c('$') | c('&') | c('(') | c(')') |
      c('*') | c('+') | c(',') | c(';') | c('=') | c('\'');
  }; //parser
}; //parser

}; //rfc3986
}; //corax

#endif //#ifndef CORAX_RFC3986_HH
