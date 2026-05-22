// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStarknetMessaging {
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32, uint256);

    function consumeMessageFromL2(
        uint256 fromAddress,
        uint256[] calldata payload
    ) external returns (bytes32);

    function startL1ToL2MessageCancellation(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external;
}

contract StarkBridge {
    IStarknetMessaging public immutable STARKNET;
    uint256 public immutable L2_BRIDGE;

    uint256 constant PROCESS_DEPOSIT_SEL =
        0x0057b3f8e0c7b4b2e97dba3e05d9b6a5f0c3e2a1b8d7c6f5e4a3b2c1d0e9f8a7;

    uint256 constant PROCESS_BATCH_SEL =
        0x00a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1;

    mapping(address => uint256) public deposits;
    address public owner;

    constructor(address _starknet, uint256 _l2Bridge) {
        STARKNET = IStarknetMessaging(_starknet);
        L2_BRIDGE = _l2Bridge;
        owner = msg.sender;
    }

    function depositToL2(address recipient, uint256 amount) external payable {
        uint256[] memory payload = new uint256[](2);
        payload[0] = uint256(uint160(recipient));
        payload[1] = amount;

        STARKNET.sendMessageToL2{value: msg.value}(
            L2_BRIDGE,
            PROCESS_DEPOSIT_SEL,
            payload
        );
        deposits[recipient] += amount;
    }

    function depositBatch(address recipient, uint256 amount, address token) external payable {
        uint256[] memory payload = new uint256[](3);
        payload[0] = uint256(uint160(recipient));
        payload[1] = amount;
        payload[2] = uint256(uint160(token));

        STARKNET.sendMessageToL2{value: msg.value}(
            L2_BRIDGE,
            PROCESS_BATCH_SEL,
            payload
        );
    }

    function depositToL2NoFee(address recipient, uint256 amount) external {
        uint256[] memory payload = new uint256[](2);
        payload[0] = uint256(uint160(recipient));
        payload[1] = amount;

        STARKNET.sendMessageToL2(
            L2_BRIDGE,
            PROCESS_DEPOSIT_SEL,
            payload
        );
    }

    function cancelDeposit(
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external {
        STARKNET.startL1ToL2MessageCancellation(
            L2_BRIDGE,
            selector,
            payload,
            nonce
        );
    }

    function withdrawFromL2(address recipient, uint256 amount) external {
        uint256[] memory payload = new uint256[](2);
        payload[0] = uint256(uint160(recipient));
        payload[1] = amount;

        STARKNET.consumeMessageFromL2(L2_BRIDGE, payload);
        payable(recipient).transfer(amount);
    }

    function cancelDepositSafe(
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external {
        require(msg.sender == owner, "not owner");
        STARKNET.startL1ToL2MessageCancellation(
            L2_BRIDGE,
            selector,
            payload,
            nonce
        );
    }

    receive() external payable {}
}
