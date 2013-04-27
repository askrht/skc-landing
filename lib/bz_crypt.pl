use Digest;
return 1;
 
sub bz_crypt {
    my ($password, $salt) = @_;
 
    my $algorithm;
    if (!defined $salt) {
        # If you don't use a salt, then people can create tables of
        # hashes that map to particular passwords, and then break your
        # hashing very easily if they have a large-enough table of common
        # (or even uncommon) passwords. So we generate a unique salt for
        # each password in the database, and then just prepend it to
        # the hash.
        $salt = generate_random_password(8);
        $algorithm = 'SHA-256';
    }
 
    # We append the algorithm used to the string. This is good because then
    # we can change the algorithm being used, in the future, without 
    # disrupting the validation of existing passwords. Also, this tells
    # us if a password is using the old "crypt" method of hashing passwords,
    # because the algorithm will be missing from the string.
    if ($salt =~ /{([^}]+)}$/) {
        $algorithm = $1;
    }
 
    my $crypted_password;
    if (!$algorithm) {
        # Wide characters cause crypt to die
        #if (Bugzilla->params->{'utf8'}) {
        #    utf8::encode($password) if utf8::is_utf8($password);
        #}
 
        # Crypt the password.
        $crypted_password = crypt($password, $salt);
 
        # HACK: Perl has bug where returned crypted password is considered
        # tainted. See http://rt.perl.org/rt3/Public/Bug/Display.html?id=59998
        #unless(tainted($password) || tainted($salt)) {
        #    trick_taint($crypted_password);
        #} 
    }
    else {
        my $hasher = Digest->new($algorithm);
        # We only want to use the first characters of the salt, no
        # matter how long of a salt we may have been passed.
        $salt = substr($salt, 0, 8);
        $hasher->add($password, $salt);
        $crypted_password = $salt . $hasher->b64digest . "{$algorithm}";
    }
 
    # Return the crypted password.
    return $crypted_password;
}