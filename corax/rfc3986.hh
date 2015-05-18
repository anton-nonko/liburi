#ifndef CORAX_RFC3986_HH
#define CORAX_RFC3986_HH

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <boost/optional.hpp>
#include <boost/tuple/tuple.hpp>

namespace corax   {
namespace rfc3986 {

namespace detail  {

typedef boost::tuple<std::string, boost::optional<std::string>> user_data;
typedef
  boost::tuple<
    boost::optional<user_data>, std::string, boost::optional<std::uint16_t>
  >
  authority;
typedef boost::tuple<boost::optional<authority>, std::string> hierarchical;
typedef
  boost::tuple<
    hierarchical, boost::optional<std::string>, boost::optional<std::string>
  >
  relative_ref;

typedef boost::tuple<boost::optional<std::string>, relative_ref> uri;

}; //detail

class uri {
  typedef boost::optional<const std::string&> ostring;
  typedef boost::optional<std::uint16_t>      ouint16;

public:
  uri(const std::string& string) {
    std::istringstream s{string};
    s >> *this;
  };

  operator std::string() const {
    std::ostringstream s;
    s << *this;
    return s.str();
  };

  friend std::ostream& operator << (std::ostream& sink, const uri& uri);
  friend std::istream& operator >> (std::istream& source, uri& uri);

  ostring scheme() const {
    return m_impl.get<0>() ? *m_impl.get<0>() : ostring{};
  };

  ostring user() const {
    auto ud = user_data();
    return ud ? ud->get<0>() : ostring{};
  };

  ostring password() const {
    auto ud = user_data();
    return ud && ud->get<1>() ? *ud->get<1>() : ostring{};
  };

  ostring host() const {
    auto a = authority();
    return a ? a->get<1>() : ostring{};
  };

  ouint16 port() const {
    auto a = authority();
    return a && a->get<2>() ? *a->get<2>() : ouint16{};
  };

  const std::string& path() const {return m_impl.get<1>().get<0>().get<1>();};

  ostring query() const {
    return m_impl.get<1>().get<1>() ? *m_impl.get<1>().get<1>() : ostring{};
  };

  ostring fragment() const {
    return m_impl.get<1>().get<2>() ? *m_impl.get<1>().get<2>() : ostring{};
  };

private:
  boost::optional<const detail::authority&> authority() const {
    return
      m_impl.get<1>().get<0>().get<0>()
      ? *m_impl.get<1>().get<0>().get<0>()
      : boost::optional<const detail::authority&>{};
  };

  boost::optional<const detail::user_data&> user_data() const {
    auto a = authority();
    return
      a && a->get<0>()
      ? *a->get<0>()
      : boost::optional<const detail::user_data&>{};
  };

  detail::uri m_impl;
}; //uri

}; //rfc3986
}; //corax

#endif //#ifndef CORAX_RFC3986_HH
