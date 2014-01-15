%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:    %{expand: %%global _httpd_moddir    %%{_libdir}/httpd/modules}}

Summary: Apache module to intercept login form submission and run PAM authentication.
Name: mod_intercept_form_submit
Version: 0.9.3
Release: 1%{?dist}
License: ASL 2.0
Group: System Environment/Daemons
URL: http://www.adelton.com/apache/mod_intercept_form_submit/
Source0: http://www.adelton.com/apache/mod_intercept_form_submit/%{name}-%{version}.tar.gz
BuildRequires: httpd-devel
BuildRequires: pkgconfig
Requires(pre): httpd
Requires: httpd
Requires: mod_authnz_pam >= 0.7

# Suppres auto-provides for module DSO
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
%{_httpd_apxs} -c mod_intercept_form_submit.c -Wall -pedantic

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
%config(noreplace) %{_httpd_modconfdir}/*.conf
%else
%config(noreplace) %{_httpd_confdir}/intercept_form_submit.conf
%endif
%{_httpd_moddir}/*.so

%changelog
* Wed Jan 15 2014 Jan Pazdziora - 0.9.3-1
- Move the processing to the middle of the fixup phase to allow
  mod_headers to process the result.

* Thu Jan 09 2014 Jan Pazdziora - 0.9.2-1
- If pam_authenticate_with_login_password is not available (mod_authnz_pam
  not loaded), skip calling it.
- Declare all functions static for proper isolation.

* Wed Jan 08 2014 Jan Pazdziora - 0.9.1-1
- Use mod_authnz_pam for the actual PAM authentication.

* Thu Dec 05 2013 Jan Pazdziora - 0.9-1
- Perform PAM account validation, not just authentication.
- Support Content-Type with charset parameter.

* Tue Nov 19 2013 Jan Pazdziora - 0.8-1
- Populate r->user as well, not just REMOTE_USER.
- Set EXTERNAL_AUTH_ERROR variable upon PAM authentication error.
- Add support for InterceptFormClearRemoteUserForSkipped.
- Add support for InterceptFormPasswordRedact.

* Thu Nov 07 2013 Jan Pazdziora - 0.7-1
- Parse the input early enough to support CGI scripts.
- Skip the authentication if REMOTE_USER is already set.

* Mon Nov 04 2013 Jan Pazdziora - 0.6-1
- Adding support for blacklists via InterceptFormLoginSkip.

* Thu Oct 31 2013 Jan Pazdziora - 0.5-1
- Initial release.
