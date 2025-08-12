I found an edge case that tests our design a bit.

Consider the following:

```go
// kube 1.35
type AllowlistEntry struct {
    Validations []string
    Name string
}

// kube 1.36
type AllowlistEntry struct {
    Validations []string
    Name string
    Digest string
    Pubkey string
}
```

Now, consider the following:

```yaml
credentialPluginAllowlist:
  - validations: ["name"]
    name: foo-bar-baz
    digest: cc2abd8963aa1ca81030a8ce35cdaf597409cd758604c13018983f8cde5d009e
```

The user has made a mistake in providing a digest without including it in the
`validations` array. However, whether the mistake results in failure or a
warning will depend on the `kubectl` version.

In Kube 1.36, the code responsible for validating the `AllowlistEntry` struct
would find that there are nonempty fields not contained in the `validations`
array; this would be considered an error since the configuration is ill-formed.

In Kube 1.35, the corresponding section in the code will have received a
version of the `AllowlistEntry` struct *without the digest field*. Because
strict unmarshaling is only used to provide warnings to the user, the
unmarshaling code will drop the `digest` field and warn the user.
