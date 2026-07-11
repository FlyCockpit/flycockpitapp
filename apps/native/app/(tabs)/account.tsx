import { useQuery } from "@tanstack/react-query";
import { Card, Surface } from "heroui-native";
import { Pressable, Text, View } from "react-native";
import { Container } from "@/components/container";
import { SignIn } from "@/components/sign-in";
import { SignUp } from "@/components/sign-up";
import { authClient } from "@/lib/auth-client";
import { appConfigQueryOptions, queryClient } from "@/utils/orpc";

export default function Account() {
  const { data: session } = authClient.useSession();
  const { data: appConfig } = useQuery(appConfigQueryOptions());
  const showSignup =
    appConfig?.signupEnabled === true || appConfig?.adminBootstrapSignupEnabled === true;
  const forceSso = appConfig?.ssoEnabled === true && appConfig.forceSso === true;

  return (
    <Container className="p-6">
      <View className="py-4 mb-6">
        <Text className="text-4xl font-bold text-foreground mb-2">Account</Text>
        <Text className="text-muted text-base">Better-Auth session state shared with the API.</Text>
      </View>

      {session?.user ? (
        <Card variant="secondary" className="p-5">
          <Text className="text-foreground text-base mb-2">
            Signed in as <Text className="font-medium">{session.user.name}</Text>
          </Text>
          <Text className="text-muted text-sm mb-4">{session.user.email}</Text>
          <Pressable
            className="bg-danger py-3 px-4 rounded-lg self-start active:opacity-70"
            onPress={() => {
              authClient.signOut();
              queryClient.invalidateQueries();
            }}
          >
            <Text className="text-foreground font-medium">Sign Out</Text>
          </Pressable>
        </Card>
      ) : forceSso ? (
        <Surface variant="secondary" className="p-4 rounded-lg">
          <Text className="text-foreground font-medium mb-1">SSO required</Text>
          <Text className="text-muted text-sm">
            This server requires SSO sign-in. Use the web app to sign in until native SSO is added
            for this product.
          </Text>
        </Surface>
      ) : (
        <View className="gap-5">
          <SignIn />
          {showSignup ? (
            <SignUp />
          ) : (
            <Surface variant="secondary" className="p-4 rounded-lg">
              <Text className="text-foreground font-medium mb-1">Signup disabled</Text>
              <Text className="text-muted text-sm">
                The server controls account creation. Set SIGNUP_ENABLED=true or configure admin
                bootstrap signup to show the create-account form.
              </Text>
            </Surface>
          )}
        </View>
      )}
    </Container>
  );
}
