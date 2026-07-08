import { useForm } from "@tanstack/react-form";
import {
  Button,
  FieldError,
  Input,
  Label,
  Spinner,
  Surface,
  TextField,
  useToast,
} from "heroui-native";
import { useRef, useState } from "react";
import { Text, TextInput, View } from "react-native";
import z from "zod";

import { authClient } from "@/lib/auth-client";
import { getAuthErrorMessage, getErrorMessage } from "@/utils/form-error";
import { orpc, queryClient } from "@/utils/orpc";

const signInSchema = z.object({
  email: z.string().trim().min(1, "Email is required").email("Enter a valid email address"),
  password: z.string().min(1, "Password is required").min(8, "Use at least 8 characters"),
});

function SignIn() {
  const passwordInputRef = useRef<TextInput>(null);
  const { toast } = useToast();
  const [needs2FA, setNeeds2FA] = useState(false);
  const [otpSent, setOtpSent] = useState(false);
  const [totpCode, setTotpCode] = useState("");
  const [isVerifying2FA, setIsVerifying2FA] = useState(false);
  const [isSendingOtp, setIsSendingOtp] = useState(false);

  const handle2FAVerify = async () => {
    setIsVerifying2FA(true);
    try {
      const result = otpSent
        ? await authClient.twoFactor.verifyOtp({ code: totpCode })
        : await authClient.twoFactor.verifyTotp({ code: totpCode });

      if (result.error) {
        toast.show({
          variant: "danger",
          label: "Invalid verification code",
        });
        return;
      }

      setNeeds2FA(false);
      setOtpSent(false);
      setTotpCode("");
      toast.show({
        variant: "success",
        label: "Signed in successfully",
      });
      queryClient.refetchQueries();
    } finally {
      setIsVerifying2FA(false);
    }
  };

  const handleSendEmailOtp = async () => {
    setIsSendingOtp(true);
    try {
      const preflight = await orpc.auth.verifyEmailTransport.call().catch(() => ({ ok: false }));
      if (!preflight.ok) {
        toast.show({
          variant: "danger",
          label: "Could not send an email code right now",
        });
        return;
      }

      const result = await authClient.twoFactor.sendOtp();
      if (result.error) {
        toast.show({
          variant: "danger",
          label: getAuthErrorMessage(result.error, "Could not send an email code right now"),
        });
        return;
      }

      setOtpSent(true);
      setTotpCode("");
      toast.show({
        variant: "success",
        label: "Verification code sent",
      });
    } finally {
      setIsSendingOtp(false);
    }
  };

  const form = useForm({
    defaultValues: {
      email: "",
      password: "",
    },
    validators: {
      onSubmit: signInSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      const result = await authClient.signIn.email({
        email: value.email.trim(),
        password: value.password,
      });

      if (result.error) {
        toast.show({
          variant: "danger",
          label: getAuthErrorMessage(result.error, "Failed to sign in"),
        });
        return;
      }

      if ((result.data as Record<string, unknown> | null)?.twoFactorRedirect) {
        setNeeds2FA(true);
        setOtpSent(false);
        setTotpCode("");
        return;
      }

      formApi.reset();
      toast.show({
        variant: "success",
        label: "Signed in successfully",
      });
      queryClient.refetchQueries();
    },
  });

  if (needs2FA) {
    return (
      <Surface variant="secondary" className="p-4 rounded-lg">
        <Text className="text-foreground font-medium mb-1">Two-factor authentication</Text>
        <Text className="text-muted text-sm mb-4">
          {otpSent
            ? "Enter the code sent to your email."
            : "Enter a code from your authenticator app."}
        </Text>

        <View className="gap-3">
          <TextField>
            <Label>Verification code</Label>
            <Input
              value={totpCode}
              onChangeText={setTotpCode}
              placeholder="123456"
              keyboardType="number-pad"
              inputMode="numeric"
              autoComplete="one-time-code"
              textContentType="oneTimeCode"
              maxLength={6}
              returnKeyType="go"
              onSubmitEditing={() => {
                if (totpCode.length === 6) {
                  handle2FAVerify();
                }
              }}
            />
          </TextField>

          <Button
            onPress={handle2FAVerify}
            isDisabled={totpCode.length !== 6 || isVerifying2FA}
            className="mt-1"
          >
            {isVerifying2FA ? (
              <Spinner size="sm" color="default" />
            ) : (
              <Button.Label>Verify</Button.Label>
            )}
          </Button>

          <Button onPress={handleSendEmailOtp} isDisabled={isSendingOtp}>
            {isSendingOtp ? (
              <Spinner size="sm" color="default" />
            ) : (
              <Button.Label>{otpSent ? "Resend email code" : "Email me a code"}</Button.Label>
            )}
          </Button>

          <Button
            onPress={() => {
              setNeeds2FA(false);
              setOtpSent(false);
              setTotpCode("");
            }}
          >
            <Button.Label>Back</Button.Label>
          </Button>
        </View>
      </Surface>
    );
  }

  return (
    <Surface variant="secondary" className="p-4 rounded-lg">
      <Text className="text-foreground font-medium mb-4">Sign In</Text>

      <form.Subscribe
        selector={(state) => ({
          isSubmitting: state.isSubmitting,
          validationError: getErrorMessage(state.errorMap.onSubmit),
        })}
      >
        {({ isSubmitting, validationError }) => {
          const formError = validationError;

          return (
            <>
              <FieldError isInvalid={!!formError} className="mb-3">
                {formError}
              </FieldError>

              <View className="gap-3">
                <form.Field name="email">
                  {(field) => (
                    <TextField>
                      <Label>Email</Label>
                      <Input
                        value={field.state.value}
                        onBlur={field.handleBlur}
                        onChangeText={field.handleChange}
                        placeholder="email@example.com"
                        keyboardType="email-address"
                        autoCapitalize="none"
                        autoComplete="email"
                        textContentType="emailAddress"
                        returnKeyType="next"
                        blurOnSubmit={false}
                        onSubmitEditing={() => {
                          passwordInputRef.current?.focus();
                        }}
                      />
                    </TextField>
                  )}
                </form.Field>

                <form.Field name="password">
                  {(field) => (
                    <TextField>
                      <Label>Password</Label>
                      <Input
                        ref={passwordInputRef}
                        value={field.state.value}
                        onBlur={field.handleBlur}
                        onChangeText={field.handleChange}
                        placeholder="••••••••"
                        secureTextEntry
                        autoComplete="password"
                        textContentType="password"
                        returnKeyType="go"
                        onSubmitEditing={form.handleSubmit}
                      />
                    </TextField>
                  )}
                </form.Field>

                <Button onPress={form.handleSubmit} isDisabled={isSubmitting} className="mt-1">
                  {isSubmitting ? (
                    <Spinner size="sm" color="default" />
                  ) : (
                    <Button.Label>Sign In</Button.Label>
                  )}
                </Button>
              </View>
            </>
          );
        }}
      </form.Subscribe>
    </Surface>
  );
}

export { SignIn };
