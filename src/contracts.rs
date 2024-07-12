use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }
);

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
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
        event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);

        event Transfer(bytes32 indexed node, address owner);

        event NewResolver(bytes32 indexed node, address resolver);

        event NewTTL(bytes32 indexed node, uint64 ttl);

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
