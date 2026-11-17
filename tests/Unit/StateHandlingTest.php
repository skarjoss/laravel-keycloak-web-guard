<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vizir\KeycloakWebGuard\Services\KeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\InMemoryKeycloakService;

class StateHandlingTest extends TestCase
{
    public function test_two_tabs_can_open_a_login_at_the_same_time(): void
    {
        $service = InMemoryKeycloakService::make();

        $service->forceState('state-tab-a');
        $service->saveState();

        $service->forceState('state-tab-b');
        $service->saveState();

        $this->assertTrue($service->validateState('state-tab-a'));
        $this->assertTrue($service->validateState('state-tab-b'));
        $this->assertFalse($service->validateState('unknown-state'));
        $this->assertFalse($service->validateState(''));
    }

    public function test_non_scalar_states_are_rejected(): void
    {
        $service = InMemoryKeycloakService::make();

        $this->assertFalse($service->validateState(['a']));
        $this->assertFalse($service->validateState(123));
        $this->assertFalse($service->validateState(null));
    }

    public function test_consume_state_only_removes_the_used_one(): void
    {
        $service = InMemoryKeycloakService::make();

        $service->forceState('state-a');
        $service->saveState();
        $service->forceState('state-b');
        $service->saveState();

        $service->consumeState('state-a');

        $this->assertFalse($service->validateState('state-a'));
        $this->assertTrue($service->validateState('state-b'));
    }

    public function test_states_expire_after_the_ttl(): void
    {
        $service = InMemoryKeycloakService::make(['stateTtl' => 10]);

        $service->forceState('old-state');
        $service->saveState();

        $states = $service->readStore(KeycloakService::KEYCLOAK_SESSION_STATES);
        $states['old-state'] = time() - 20;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_STATES, $states);

        $this->assertFalse($service->validateState('old-state'));
    }

    public function test_only_the_most_recent_states_are_kept(): void
    {
        $service = InMemoryKeycloakService::make(['maxStates' => 3]);

        foreach (['s1', 's2', 's3', 's4'] as $state) {
            $service->forceState($state);
            $service->saveState();
        }

        $states = $service->readStore(KeycloakService::KEYCLOAK_SESSION_STATES);

        $this->assertCount(3, $states);
        $this->assertArrayNotHasKey('s1', $states);
        $this->assertArrayHasKey('s4', $states);
    }

    public function test_legacy_single_state_is_still_accepted(): void
    {
        $service = InMemoryKeycloakService::make();
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_STATE, 'legacy-state');

        $this->assertTrue($service->validateState('legacy-state'));
    }

    public function test_failed_state_counter_increments_and_resets(): void
    {
        $service = InMemoryKeycloakService::make();

        $this->assertSame(1, $service->registerFailedState());
        $this->assertSame(2, $service->registerFailedState());

        $service->forgetFailedState();

        $this->assertSame(1, $service->registerFailedState());
    }
}
