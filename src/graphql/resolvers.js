import movies from '../db/movies';
import users from '../db/users';
import { AuthenticationError, ForbiddenError } from 'apollo-server';
import bcrypt from 'bcrypt';
import sha256 from 'crypto-js/sha256';
import rand from 'csprng';

const resolvers = {
	Query: {
		movies: () => movies,
		movie: (_, { id }) => {
			return movies.filter(movie => movie.id === id)[0];
		},
		users: (_, __, {user}) => {
			if (!user) throw new AuthenticationError('Not Authenticated');
			if (!user.roles.includes('admin'))
				throw new ForbiddenError('Not Authorized');

			return users;
		},
		user: (_, {ID}) => {
			return users.filter(user => user.ID === ID)[0];
		},
		me: (_, __, { user }) => {
			if (!user) throw new AuthenticationError('Not Authenticated');

			return user;
		}
	},
	Mutation: {
		addMovie: (_, { name, rating }) => {
			if (movies.find(movie => movie.name === name)) return null;

			const newMovie = {
				id: movies.length + 1,
				name,
				rating
			};
			movies.push(newMovie);
			return newMovie;
		},
		addUser: (_, { ID, password }) => {
			if (users.find(user => user.ID === ID)) return null;

			const newUser = {
				id: users.length + 1,
				ID,
				password
			};
			users.push(newUser);
			return newUser;
		},
		signUp: (_, { name, ID, password }) => {
			if (users.find(user => user.ID === ID)) {
				return false;
			}

			bcrypt.hash(password, 10, function(err, passwordHash) {
				const newUser = {
					id: users.length + 1,
					name,
					ID,
					passwordHash,
					role: ['user'],
					token: ''
				};
				users.push(newUser);
			});

			return true;
		},
		login: (_, { ID, password }) => {
			let user = users.find(user => user.ID === ID);

			if (!user) return 'none user'; // 해당 ID가 없을 때
			if (user.token) return null; // 해당 ID로 이미 로그인되어 있을 때
			if (!bcrypt.compareSync(password, user.passwordHash)) return null; // 비밀번호가 일치하지 않을 때

			user.token = sha256(rand(160, 36) + ID + password).toString();
			return user;
		},
		logout: (_, __, { user }) => {
			if (user?.token) { // 로그인 상태라면(토큰이 존재하면)
				user.token = '';
				return true;
			}

			throw new AuthenticationError('Not Authenticated'); // 로그인되어 있지 않거나 로그인 토큰이 없을 때
		}
	}
};

export default resolvers;
