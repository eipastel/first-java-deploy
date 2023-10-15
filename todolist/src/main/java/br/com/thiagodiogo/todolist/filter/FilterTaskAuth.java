package br.com.thiagodiogo.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.thiagodiogo.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

            var servletPath = request.getServletPath();
            if(servletPath.startsWith("/tasks/")) {
                // Pegando a autorização e decodificando-a
                var authorization = request.getHeader("Authorization");

                // Tirando a palavra "Basic" da senha codificada
                var codedAuthorization = authorization.substring("Basic".length()).trim();
                
                // Decodificando da base 64
                byte[] decodedPassword = Base64.getDecoder().decode(codedAuthorization);
                
                // Transformando a senha decodificada em string
                var AuthString = new String(decodedPassword);

                // Separando o usuário da senha (em um array)
                String[] credentials = AuthString.split(":");

                // Variáveis do usuário e senha decodificados
                String username = credentials[0];
                String password = credentials[1];

                // Validar se o usuário existe
                var user = this.userRepository.findByUsername(username);
                if(user == null) {
                    response.sendError(401);
                } else {
                    // Validar se a senha está correta
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    // Se for correta
                    if(passwordVerify.verified) {
                        // Seguir viajem caso esteja tudo correto.
                        request.setAttribute("idUser", user.getId());
                        filterChain.doFilter(request, response);
                    // Se não for correta
                    } else {
                        response.sendError(401);
                    }
                }
            } else {
                filterChain.doFilter(request, response);
            }
    }

    
    
}
