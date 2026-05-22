#[starknet::contract]
mod BridgeSafe {
    use starknet::EthAddress;
    use starknet::ContractAddress;
    use starknet::syscalls::send_message_to_l1_syscall;

    #[storage]
    struct Storage {
        l1_bridge: EthAddress,
        owner: ContractAddress,
        balances: LegacyMap<ContractAddress, u256>,
        consumed_nonces: LegacyMap<felt252, bool>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, l1_bridge: EthAddress, owner: ContractAddress) {
        self.l1_bridge.write(l1_bridge);
        self.owner.write(owner);
    }

    #[l1_handler]
    fn process_deposit(
        ref self: ContractState,
        from_address: EthAddress,
        recipient: ContractAddress,
        amount_low: u128,
        amount_high: u128,
    ) {
        assert(from_address == self.l1_bridge.read(), 'unauthorized: bad l1 sender');
        let amount: u256 = u256 { low: amount_low, high: amount_high };
        let current = self.balances.read(recipient);
        self.balances.write(recipient, current + amount);
    }

    #[l1_handler]
    fn process_withdrawal_request(
        ref self: ContractState,
        from_address: EthAddress,
        recipient: ContractAddress,
        amount_low: u128,
        amount_high: u128,
        nonce: felt252,
    ) {
        assert(from_address == self.l1_bridge.read(), 'unauthorized: bad l1 sender');
        assert(!self.consumed_nonces.read(nonce), 'nonce already consumed');
        self.consumed_nonces.write(nonce, true);

        let amount: u256 = u256 { low: amount_low, high: amount_high };
        let current = self.balances.read(recipient);
        assert(current >= amount, 'insufficient balance');
        self.balances.write(recipient, current - amount);

        let mut payload: Array<felt252> = ArrayTrait::new();
        payload.append(recipient.into());
        payload.append(amount_low.into());
        payload.append(amount_high.into());
        send_message_to_l1_syscall(self.l1_bridge.read().into(), payload.span());
    }

    #[view]
    fn get_balance(self: @ContractState, account: ContractAddress) -> u256 {
        self.balances.read(account)
    }
}
