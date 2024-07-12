use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    /**
     * @dev Interface of the ERC165 standard, as defined in the
     * https://eips.ethereum.org/EIPS/eip-165[EIP].
     *
     * Implementers can declare support of contract interfaces, which can then be
     * queried by others ({ERC165Checker}).
     *
     * For an implementation, see {ERC165}.
     */
    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }
);

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    /**
     * Interface for the legacy (ETH-only) addr function.
     */
    interface IAddrResolver {
        event AddrChanged(bytes32 indexed node, address a);
        function addr(bytes32 node) external view returns (address payable);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IExtendedResolver {
        function resolve(
            bytes memory name,
            bytes memory data
        ) external view returns (bytes memory);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IOffChain {
        error OffchainLookup(
            address sender,
            string[] urls,
            bytes callData,
            bytes4 callbackFunction,
            bytes extraData
        );
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ENS {
        // Logged when the owner of a node assigns a new owner to a subnode.
        event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);

        // Logged when the owner of a node transfers ownership to a new account.
        event Transfer(bytes32 indexed node, address owner);

        // Logged when the resolver for a node changes.
        event NewResolver(bytes32 indexed node, address resolver);

        // Logged when the TTL of a node changes
        event NewTTL(bytes32 indexed node, uint64 ttl);

        // Logged when an operator is added or removed.
        event ApprovalForAll(
            address indexed owner,
            address indexed operator,
            bool approved
        );

        function setRecord(
            bytes32 node,
            address owner,
            address resolver,
            uint64 ttl
        ) external;

        function setSubnodeRecord(
            bytes32 node,
            bytes32 label,
            address owner,
            address resolver,
            uint64 ttl
        ) external;

        function setSubnodeOwner(
            bytes32 node,
            bytes32 label,
            address owner
        ) external returns (bytes32);

        function setResolver(bytes32 node, address resolver) external;

        function setOwner(bytes32 node, address owner) external;

        function setTTL(bytes32 node, uint64 ttl) external;

        function setApprovalForAll(address operator, bool approved) external;

        function owner(bytes32 node) external view returns (address);

        function resolver(bytes32 node) external view returns (address);

        function ttl(bytes32 node) external view returns (uint64);

        function recordExists(bytes32 node) external view returns (bool);

        function isApprovedForAll(
            address owner,
            address operator
        ) external view returns (bool);
    }
}
