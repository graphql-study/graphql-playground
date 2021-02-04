import {gql} from 'apollo-server';

const typeDefs = gql`

	type User {
		id: Int!
		name: String!
		ID: String!
		passwordHash: String
		role: [String!]!
		token: String
	}

	type Movie {
		id: Int!
		name: String!
		rating: Int!
	}

	type Query {
		movies: [Movie!]!
		movie(id: Int!): Movie
		users: [User]!
		user(ID: String!): User
		me: User!
	}

	type Mutation {
		addMovie(name: String!, rating: Int!): Movie!
		addUser(ID: String!, password: String!): User
		signUp(name: String!, ID: String!, password: String!): Boolean!
		login(ID: String!, password: String!): User
		logout: Boolean!
	}
`;

export default typeDefs;
