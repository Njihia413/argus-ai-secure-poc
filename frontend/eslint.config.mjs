/** @type {import('eslint').Linter.Config[]} */
const eslintConfig = [
  {
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "CallExpression[callee.object.name='sessionStorage'][callee.property.name='getItem'][arguments.0.value='user']",
          message:
            "Do not read sessionStorage 'user' directly. Use useAuthStore() or getAuthUser() from @/store/auth instead.",
        },
      ],
    },
  },
];

export default eslintConfig;
