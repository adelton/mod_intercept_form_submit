%{!?_httpd_mmn: %{expand: %%global _httpd_mmn %%(cat %{_includedir}/httpd/.mmn || echo 0-0)}}
%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:    %{expand: %%global _httpd_moddir    %%{_libdir}/httpd/modules}}

Summary: Apache module to intercept login form submission and run PAM authentication
Name: mod_intercept_form_submit
Version: 0.9.7
Release: 1%{?dist}
License: ASL 2.0
Group: System Environment/Daemons
URL: http://www.adelton.com/apache/mod_intercept_form_submit/
Source0: http://www.adelton.com/apache/mod_intercept_form_submit/%{name}-%{version}.tar.gz
BuildRequires: httpd-devel
BuildRequires: pkgconfig
Requires(pre): httpd
Requires: httpd-mmn = %{_httpd_mmn}
Requires: mod_authnz_pam >= 0.7

# Suppres auto-provides for module DSO per
# https://fedoraproject.org/wiki/Packaging:AutoProvidesAndRequiresFiltering#Summary
%{?filter_provides_in: %filter_provides_in %{_libdir}/httpd/modules/.*\.so$}
%{?filter_setup}

%description
mod_intercept_form_submit can intercept submission of application login
forms. It retrieves the login and password information from the POST
HTTP request, runs PAM authentication with those credentials, and sets
the REMOTE_USER environment variable if the authentication passes.

%prep
%setup -q -n %{name}-%{version}

%build
%{_httpd_apxs} -c -Wc,"%{optflags} -Wall -pedantic -std=c99" mod_intercept_form_submit.c

%install
rm -rf $RPM_BUILD_ROOT
install -Dm 755 .libs/mod_intercept_form_submit.so $RPM_BUILD_ROOT%{_httpd_moddir}/mod_intercept_form_submit.so

%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
# httpd >= 2.4.x
install -Dp -m 0644 intercept_form_submit.conf $RPM_BUILD_ROOT%{_httpd_modconfdir}/55-intercept_form_submit.conf
%else
# httpd <= 2.2.x
install -Dp -m 0644 intercept_form_submit.conf $RPM_BUILD_ROOT%{_httpd_confdir}/intercept_form_submit.conf
%endif

%files
%doc README LICENSE docs/*
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
%config(noreplace) %{_httpd_modconfdir}/55-intercept_form_submit.conf
%else
%config(noreplace) %{_httpd_confdir}/intercept_form_submit.conf
%endif
%{_httpd_moddir}/*.so

%changelog
* Tue May 13 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.7-1
- No longer call lookup_identity_hook explicitly, hook order does
  the same.
- Silence compile warnings by specifying C99.

* Tue Apr 15 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.6-1
- Add support for InterceptFormLoginRealms.

* Thu Jan 30 2014 Jan Pazdziora <jpazdziora@redhat.com> - 0.9.5-1
- 1058809 - .spec changes for Fedora package review.

